from flask import Flask, request, redirect, jsonify, session
import psycopg2
import os
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallback-secret")

DATABASE_URL = os.environ["DATABASE_URL"]

SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
DATABASE = os.path.join(BASE_DIR, "users.db")



def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


def init_database():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            otp_code TEXT,
            is_verified BOOLEAN DEFAULT FALSE,
            otp_expires_at TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database initialized")


@app.before_first_request
def startup():
    init_database()


def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp_email(email, otp):
    msg = EmailMessage()
    msg["Subject"] = "Your OTP Code"
    msg["From"] = SENDER_EMAIL
    msg["To"] = email
    msg.set_content(f"Your OTP is {otp}. It expires in 10 minutes.")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(SENDER_EMAIL, EMAIL_PASSWORD)
        smtp.send_message(msg)


@app.route("/")
def index():
    return redirect("/register")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].lower().strip()
        otp = generate_otp()
        expires = datetime.utcnow() + timedelta(minutes=10)

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("DELETE FROM users WHERE email=%s AND is_verified=false", (email,))
        cur.execute("""
            INSERT INTO users (email, otp_code, otp_expires_at, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            email, otp, expires,
            request.remote_addr,
            request.headers.get("User-Agent", "unknown")
        ))

        conn.commit()
        cur.close()
        conn.close()

        send_otp_email(email, otp)
        session["verify_email"] = email
        return redirect("/verify")

    return """
    <form method="post">
        <input type="email" name="email" required />
        <button>Send OTP</button>
    </form>
    """


@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("verify_email")
    if not email:
        return redirect("/")

    if request.method == "POST":
        otp = request.form["otp"]

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT id FROM users
            WHERE email=%s AND otp_code=%s AND otp_expires_at > NOW()
        """, (email, otp))

        user = cur.fetchone()

        if user:
            cur.execute(
                "UPDATE users SET is_verified=true WHERE email=%s", (email,)
            )
            conn.commit()
            session.pop("verify_email")
            cur.close()
            conn.close()
            return "✅ Verified successfully"

        cur.close()
        conn.close()
        return "❌ Invalid or expired OTP"

    return """
    <form method="post">
        <input name="otp" maxlength="6" required />
        <button>Verify</button>
    </form>
    """


@app.route("/api/verified_emails")
def verified_emails():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE is_verified=true")
    emails = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()
    return jsonify(emails)


# 🚫 DO NOT RUN APP HERE ON RAILWAY
if __name__ == "__main__":
    pass
