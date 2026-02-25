import base64
import os
import sqlite3
import smtplib
from datetime import datetime, timezone
from io import BytesIO
from itertools import islice
from email.message import EmailMessage

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    url_for,
    flash,
    session,
    send_file,
)
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "memory_capsule.db")

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY is not set.")
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".xls",
    ".xlsx",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".mp4",
}


def get_db() -> sqlite3.Connection | None:
    try:
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH, timeout=5)
            g.db.row_factory = sqlite3.Row
            try:
                g.db.execute("PRAGMA journal_mode=WAL")
            except sqlite3.Error:
                pass
        return g.db
    except sqlite3.Error:
        return None


@app.teardown_appcontext
def close_db(exception: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> bool:
    db = get_db()
    if db is None:
        return False
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS capsules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_text BLOB NOT NULL,
                unlock_time TEXT NOT NULL,
                server_key_half TEXT NOT NULL,
                sender_email TEXT NOT NULL,
                recipient_email TEXT NOT NULL
            )
            """
        )

        columns = [row[1] for row in db.execute("PRAGMA table_info(capsules)").fetchall()]
        if "encrypted_text" not in columns:
            db.execute(
                "ALTER TABLE capsules ADD COLUMN encrypted_text BLOB NOT NULL DEFAULT x''"
            )
        if "server_key_half" not in columns:
            db.execute(
                "ALTER TABLE capsules ADD COLUMN server_key_half TEXT NOT NULL DEFAULT ''"
            )
        if "sender_email" not in columns:
            db.execute(
                "ALTER TABLE capsules ADD COLUMN sender_email TEXT NOT NULL DEFAULT ''"
            )
        if "recipient_email" not in columns:
            db.execute(
                "ALTER TABLE capsules ADD COLUMN recipient_email TEXT NOT NULL DEFAULT ''"
            )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS capsule_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capsule_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                data BLOB NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (capsule_id) REFERENCES capsules(id)
            )
            """
        )
        db.commit()
        return True
    except sqlite3.Error:
        return False


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_datetime(value: str) -> datetime:
    local_tz = datetime.now().astimezone().tzinfo
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=local_tz)
    return parsed.astimezone(timezone.utc)


def is_allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def get_file_size(file_storage) -> int:
    stream = file_storage.stream
    current = stream.tell()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(current)
    return size


def split_key_halves(key_bytes: bytes) -> tuple[bytes, bytes]:
    iterator = iter(key_bytes)
    first_half = bytes(islice(iterator, 16))
    second_half = bytes(iterator)
    return first_half, second_half


def send_key_email(recipient_email: str, user_key_half: str) -> bool:
    email_user = os.environ.get("EMAIL_USER")
    email_pass = os.environ.get("EMAIL_PASS")
    if not email_user or not email_pass:
        return False

    message = EmailMessage()
    message["Subject"] = "Your Digital Memory Capsule Key"
    message["From"] = email_user
    message["To"] = recipient_email
    message.set_content(
        "Your Digital Memory Capsule key half is below.\n\n"
        f"{user_key_half}\n\n"
        "You will need this key to unlock the capsule when the time arrives."
    )

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(email_user, email_pass)
            server.send_message(message)
        return True
    except smtplib.SMTPException:
        return False


@app.route("/", methods=["GET", "POST"])
def index():
    if not init_db():
        flash("Database is not available right now. Please try again later.")
        return render_template("index.html", capsules=[], encrypted_preview=None)

    if request.method == "POST":
        message = request.form.get("message", "").strip()
        unlock_time = request.form.get("unlock_time", "").strip()
        sender_email = request.form.get("sender_email", "").strip()
        recipient_email = request.form.get("recipient_email", "").strip()
        files = request.files.getlist("files")

        if not message or not unlock_time or not sender_email or not recipient_email:
            flash("Message, unlock time, sender email, and recipient email are required.")
            return redirect(url_for("index"))

        try:
            parsed_unlock = parse_datetime(unlock_time)
        except ValueError:
            flash("Please enter a valid unlock date and time.")
            return redirect(url_for("index"))

        try:
            capsule_key = Fernet.generate_key()
            key_bytes = base64.urlsafe_b64decode(capsule_key)
            server_half, user_half = split_key_halves(key_bytes)

            # Reconstruction: base64-decode server + user halves, join, then base64-encode.
            server_half_b64 = base64.urlsafe_b64encode(server_half).decode("utf-8")
            user_half_b64 = base64.urlsafe_b64encode(user_half).decode("utf-8")

            fernet = Fernet(capsule_key)
            encrypted = fernet.encrypt(message.encode("utf-8"))
        except Exception:
            flash("Encryption failed. Please try again.")
            return redirect(url_for("index"))

        validated_files = []
        for file_item in files:
            if not file_item or not file_item.filename:
                continue
            filename = secure_filename(file_item.filename)
            if not filename:
                flash("One of the files has an invalid name.")
                return redirect(url_for("index"))
            if not is_allowed_file(filename):
                flash("File type not allowed: " + filename)
                return redirect(url_for("index"))
            size = get_file_size(file_item)
            if size > app.config["MAX_CONTENT_LENGTH"]:
                flash("File too large (max 30MB): " + filename)
                return redirect(url_for("index"))
            validated_files.append((file_item, filename, size))

        db = get_db()
        if db is None:
            flash("Database is not available right now. Please try again later.")
            return redirect(url_for("index"))

        try:
            cursor = db.execute(
                """
                INSERT INTO capsules (
                    encrypted_text,
                    unlock_time,
                    server_key_half,
                    sender_email,
                    recipient_email
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    encrypted,
                    parsed_unlock.isoformat().replace("+00:00", "Z"),
                    server_half_b64,
                    sender_email,
                    recipient_email,
                ),
            )
            capsule_id = cursor.lastrowid

            for file_item, filename, size in validated_files:
                data = file_item.read()
                file_item.stream.seek(0)
                encrypted_data = fernet.encrypt(data)
                db.execute(
                    """
                    INSERT INTO capsule_files (capsule_id, filename, content_type, data, size, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        capsule_id,
                        filename,
                        file_item.mimetype or "application/octet-stream",
                        encrypted_data,
                        size,
                        utcnow_iso(),
                    ),
                )

            db.commit()
        except sqlite3.Error as exc:
            if "locked" in str(exc).lower():
                flash("Database is busy. Close any DB viewer and try again.")
            else:
                flash("Unable to save the capsule. Please try again.")
            return redirect(url_for("index"))

        if not send_key_email(recipient_email, user_half_b64):
            flash("Capsule saved, but email delivery failed.")

        flash("Capsule saved successfully.")
        session["encrypted_preview"] = base64.b64encode(encrypted).decode("utf-8")
        session["user_key_half"] = user_half_b64
        return redirect(url_for("index"))

    db = get_db()
    if db is None:
        flash("Database is not available right now. Please try again later.")
        return render_template("index.html", capsules=[], encrypted_preview=None)

    capsules = []
    try:
        rows = db.execute(
            "SELECT id, encrypted_text, unlock_time FROM capsules ORDER BY id DESC"
        ).fetchall()
        for row in rows:
            preview = base64.b64encode(row["encrypted_text"]).decode("utf-8")
            capsules.append(
                {
                    "id": row["id"],
                    "unlock_time": row["unlock_time"],
                    "encrypted_preview": preview,
                }
            )
    except sqlite3.Error:
        flash("Unable to load capsules right now.")

    encrypted_preview = session.pop("encrypted_preview", None)
    user_key_half = session.pop("user_key_half", None)
    return render_template(
        "index.html",
        capsules=capsules,
        encrypted_preview=encrypted_preview,
        user_key_half=user_key_half,
    )


@app.route("/unlock/<int:capsule_id>", methods=["GET", "POST"])
def unlock(capsule_id: int):
    if not init_db():
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    db = get_db()
    if db is None:
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    try:
        row = db.execute(
            """
            SELECT id, encrypted_text, unlock_time, server_key_half, recipient_email
            FROM capsules
            WHERE id = ?
            """,
            (capsule_id,),
        ).fetchone()
    except sqlite3.Error:
        flash("Unable to load the capsule right now.")
        return redirect(url_for("index"))

    if row is None:
        flash("That capsule does not exist.")
        return redirect(url_for("index"))

    try:
        unlock_at = parse_datetime(row["unlock_time"])
    except ValueError:
        flash("This capsule has an invalid unlock time.")
        return redirect(url_for("index"))

    if datetime.now(timezone.utc) < unlock_at:
        flash("This capsule is still locked.")
        return redirect(url_for("index"))

    decrypted = None
    unlock_status = "locked"
    if request.method == "POST":
        user_email = request.form.get("user_email", "").strip().lower()
        user_key_half = request.form.get("user_key_half", "").strip()
        recipient_email = (row["recipient_email"] or "").strip().lower()

        if not user_email or not user_key_half:
            flash("Please provide your email and key half to unlock this capsule.")
            unlock_status = "missing"
        elif user_email != recipient_email:
            flash("This email is not authorized to unlock the capsule.")
            unlock_status = "invalid"
        else:
            try:
                server_half = base64.urlsafe_b64decode(row["server_key_half"])
                user_half = base64.urlsafe_b64decode(user_key_half)
                full_key = base64.urlsafe_b64encode(server_half + user_half)
                fernet = Fernet(full_key)
                decrypted = fernet.decrypt(row["encrypted_text"]).decode("utf-8")
                session[f"user_key_half_{row['id']}"] = user_key_half
                session[f"user_email_{row['id']}"] = user_email
                unlock_status = "success"
            except (InvalidToken, ValueError, Exception):
                flash("Invalid key half. Please check and try again.")
                unlock_status = "invalid"

    files = []
    if decrypted is not None:
        try:
            file_rows = db.execute(
                """
                SELECT id, filename, content_type, size
                FROM capsule_files
                WHERE capsule_id = ?
                ORDER BY id ASC
                """,
                (capsule_id,),
            ).fetchall()
            files = [dict(file_row) for file_row in file_rows]
        except sqlite3.Error:
            flash("Unable to load files right now.")

    return render_template(
        "unlock.html",
        capsule={
            "id": row["id"],
            "message": decrypted,
            "unlock_time": row["unlock_time"],
            "files": files,
        },
        unlock_status=unlock_status,
    )


@app.route("/download/<int:file_id>", methods=["GET"])
def download_file(file_id: int):
    if not init_db():
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    db = get_db()
    if db is None:
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    try:
        row = db.execute(
            """
            SELECT f.id, f.filename, f.content_type, f.data, c.unlock_time, c.server_key_half, c.id AS capsule_id
            FROM capsule_files f
            JOIN capsules c ON c.id = f.capsule_id
            WHERE f.id = ?
            """,
            (file_id,),
        ).fetchone()
    except sqlite3.Error:
        flash("Unable to load the file right now.")
        return redirect(url_for("index"))

    if row is None:
        flash("File not found.")
        return redirect(url_for("index"))

    try:
        unlock_at = parse_datetime(row["unlock_time"])
    except ValueError:
        flash("This capsule has an invalid unlock time.")
        return redirect(url_for("index"))

    if datetime.now(timezone.utc) < unlock_at:
        flash("This capsule is still locked.")
        return redirect(url_for("index"))

    user_key_half = session.get(f"user_key_half_{row['capsule_id']}")
    if not user_key_half:
        flash("Please unlock the capsule with your key half first.")
        return redirect(url_for("unlock", capsule_id=row["capsule_id"]))

    try:
        server_half = base64.urlsafe_b64decode(row["server_key_half"])
        user_half = base64.urlsafe_b64decode(user_key_half)
        full_key = base64.urlsafe_b64encode(server_half + user_half)
        fernet = Fernet(full_key)
        decrypted = fernet.decrypt(row["data"])
    except (InvalidToken, ValueError, Exception):
        flash("Unable to decrypt the file. Check your key half and try again.")
        return redirect(url_for("unlock", capsule_id=row["capsule_id"]))

    return send_file(
        BytesIO(decrypted),
        download_name=row["filename"],
        mimetype=row["content_type"],
        as_attachment=True,
    )


@app.route("/capsules", methods=["GET"])
def list_capsules():
    if not init_db():
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    db = get_db()
    if db is None:
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    try:
        rows = db.execute(
            "SELECT id, unlock_time FROM capsules ORDER BY id DESC"
        ).fetchall()
    except sqlite3.Error:
        flash("Unable to load capsules right now.")
        return redirect(url_for("index"))

    now_utc = datetime.now(timezone.utc)
    capsules = []
    for row in rows:
        try:
            unlock_at = parse_datetime(row["unlock_time"])
        except ValueError:
            unlock_at = now_utc
        status = "Unlocked" if now_utc >= unlock_at else "Locked"
        capsules.append(
            {
                "id": row["id"],
                "unlock_time": row["unlock_time"],
                "status": status,
            }
        )

    return render_template("capsules.html", capsules=capsules)


@app.route("/clear", methods=["POST"])
def clear_capsules():
    if not init_db():
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    db = get_db()
    if db is None:
        flash("Database is not available right now. Please try again later.")
        return redirect(url_for("index"))

    try:
        db.execute("DELETE FROM capsule_files")
        db.execute("DELETE FROM capsules")
        db.commit()
    except sqlite3.Error:
        flash("Unable to clear capsules right now.")
        return redirect(url_for("index"))

    flash("All capsules and files have been cleared.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
