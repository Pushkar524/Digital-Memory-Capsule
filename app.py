import base64
import os
import sqlite3
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, g, redirect, render_template, request, url_for, flash, session

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "memory_capsule.db")
KEY_PATH = os.path.join(BASE_DIR, "fernet.key")

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")


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


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS capsules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message BLOB NOT NULL,
            unlock_time TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()


def utcnow_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", ""))


@app.route("/", methods=["GET", "POST"])
def index():
    init_db()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()
        unlock_time = request.form.get("unlock_time", "").strip()

        if not title or not message or not unlock_time:
            flash("Title, message, and unlock time are required.")
            return redirect(url_for("index"))

        try:
            parsed_unlock = parse_datetime(unlock_time)
        except ValueError:
            flash("Unlock time must be a valid datetime.")
            return redirect(url_for("index"))

        fernet = get_fernet()
        encrypted = fernet.encrypt(message.encode("utf-8"))

        db = get_db()
        db.execute(
            """
            INSERT INTO capsules (title, message, unlock_time, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (title, encrypted, parsed_unlock.isoformat(), utcnow_iso()),
        )
        db.commit()
        flash("Capsule saved.")
        session["encrypted_preview"] = base64.b64encode(encrypted).decode("utf-8")
        return redirect(url_for("index"))

    db = get_db()
    rows = db.execute(
        "SELECT id, title, message, unlock_time, created_at FROM capsules ORDER BY id DESC"
    ).fetchall()
    capsules = []
    for row in rows:
        preview = base64.b64encode(row["message"]).decode("utf-8")
        capsules.append(
            {
                "id": row["id"],
                "title": row["title"],
                "unlock_time": row["unlock_time"],
                "created_at": row["created_at"],
                "encrypted_preview": preview,
            }
        )

    encrypted_preview = session.pop("encrypted_preview", None)
    return render_template(
        "index.html",
        capsules=capsules,
        encrypted_preview=encrypted_preview,
    )


@app.route("/unlock/<int:capsule_id>", methods=["GET"])
def unlock(capsule_id: int):
    init_db()
    db = get_db()
    row = db.execute(
        "SELECT id, title, message, unlock_time FROM capsules WHERE id = ?",
        (capsule_id,),
    ).fetchone()

    if row is None:
        flash("Capsule not found.")
        return redirect(url_for("index"))

    unlock_at = parse_datetime(row["unlock_time"])
    if datetime.utcnow() < unlock_at:
        flash("This capsule is still locked.")
        return redirect(url_for("index"))

    fernet = get_fernet()
    try:
        decrypted = fernet.decrypt(row["message"]).decode("utf-8")
    except InvalidToken:
        decrypted = "[Unable to decrypt message]"

    return render_template(
        "unlock.html",
        capsule={
            "id": row["id"],
            "title": row["title"],
            "message": decrypted,
            "unlock_time": row["unlock_time"],
        },
    )


if __name__ == "__main__":
    app.run(debug=True)
