import base64
import os
import sqlite3
from datetime import datetime, timezone
from io import BytesIO

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
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
KEY_PATH = os.path.join(BASE_DIR, "fernet.key")

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
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


def load_or_create_key() -> bytes:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as key_file:
            return key_file.read().strip()

    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as key_file:
        key_file.write(key)
    return key


def get_fernet() -> Fernet:
    return Fernet(load_or_create_key())


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
                server_key_half TEXT NOT NULL
            )
            """
        )

        columns = [row[1] for row in db.execute("PRAGMA table_info(capsules)").fetchall()]
        legacy_columns = {"title", "message", "created_at"}
        needs_migration = (
            "encrypted_text" not in columns
            or "server_key_half" not in columns
            or any(col in columns for col in legacy_columns)
        )

        if needs_migration:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS capsules_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_text BLOB NOT NULL,
                    unlock_time TEXT NOT NULL,
                    server_key_half TEXT NOT NULL
                )
                """
            )

            if "message" in columns:
                db.execute(
                    """
                    INSERT INTO capsules_new (id, encrypted_text, unlock_time, server_key_half)
                    SELECT id, message, unlock_time, '' FROM capsules
                    """
                )
            else:
                db.execute(
                    """
                    INSERT INTO capsules_new (id, encrypted_text, unlock_time, server_key_half)
                    SELECT id, encrypted_text, unlock_time, '' FROM capsules
                    """
                )

            db.execute("DROP TABLE capsules")
            db.execute("ALTER TABLE capsules_new RENAME TO capsules")

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


@app.route("/", methods=["GET", "POST"])
def index():
    if not init_db():
        flash("Database is not available right now. Please try again later.")
        return render_template("index.html", capsules=[], encrypted_preview=None)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()
        unlock_time = request.form.get("unlock_time", "").strip()
        files = request.files.getlist("files")

        if not title or not message or not unlock_time:
            flash("Title, message, and unlock time are required.")
            return redirect(url_for("index"))

        try:
            parsed_unlock = parse_datetime(unlock_time)
        except ValueError:
            flash("Please enter a valid unlock date and time.")
            return redirect(url_for("index"))

        try:
            capsule_key = Fernet.generate_key()
            key_bytes = base64.urlsafe_b64decode(capsule_key)
            server_half = key_bytes[:16]
            user_half = key_bytes[16:]

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
                INSERT INTO capsules (encrypted_text, unlock_time, server_key_half)
                VALUES (?, ?, ?)
                """,
                (
                    encrypted,
                    parsed_unlock.isoformat().replace("+00:00", "Z"),
                    server_half_b64,
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
    return render_template(
        "index.html",
        capsules=capsules,
        encrypted_preview=encrypted_preview,
    )


@app.route("/unlock/<int:capsule_id>", methods=["GET"])
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
            "SELECT id, encrypted_text, unlock_time FROM capsules WHERE id = ?",
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

    try:
        fernet = get_fernet()
        decrypted = fernet.decrypt(row["encrypted_text"]).decode("utf-8")
    except (InvalidToken, Exception):
        decrypted = "[Unable to decrypt message]"

    files = []
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
            SELECT f.id, f.filename, f.content_type, f.data, c.unlock_time
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

    try:
        fernet = get_fernet()
        decrypted = fernet.decrypt(row["data"])
    except (InvalidToken, Exception):
        flash("Unable to decrypt the file.")
        return redirect(url_for("index"))

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
    app.run(debug=True)
