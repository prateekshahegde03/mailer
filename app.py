
import os
import re
import time
import sqlite3
import hmac
from pathlib import Path
from urllib.parse import urlparse, urljoin

import pandas as pd
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session
)
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps


# ==========================================
# CONFIGURATION
# ==========================================

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing from environment variables.")

if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError(
        "ADMIN_USERNAME and ADMIN_PASSWORD must be configured."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Secure session cookie settings
is_production = (
    os.getenv("RENDER") is not None
    or os.getenv("FLASK_ENV") == "production"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8
)

# CSRF protection for all POST forms
csrf = CSRFProtect(app)

# SMTP configuration
app.config["MAIL_SERVER"] = os.getenv(
    "MAIL_SERVER", "smtp.hostinger.com"
)
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 465))
app.config["MAIL_USE_SSL"] = os.getenv(
    "MAIL_USE_SSL", "True"
).lower() == "true"
app.config["MAIL_USE_TLS"] = os.getenv(
    "MAIL_USE_TLS", "False"
).lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv(
    "MAIL_DEFAULT_SENDER"
)

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
SEND_DELAY_SECONDS = 2

mail = Mail(app)

DB_PATH = Path(
    os.getenv(
        "DB_PATH",
        str(Path(__file__).resolve().parent / "trec_mailer.db")
    )
)

unsubscribe_serializer = URLSafeTimedSerializer(
    SECRET_KEY,
    salt="trec-mailer-unsubscribe"
)


# ==========================================
# AUTHENTICATION
# ==========================================

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(
                url_for("login", next=request.url)
            )
        return view(*args, **kwargs)
    return wrapped_view


@app.before_request
def require_admin_login():
    # Public pages and static assets
    allowed_endpoints = {
        "login",
        "logout",
        "unsubscribe",
        "static"
    }

    if request.endpoint in allowed_endpoints:
        return None

    if not session.get("admin_logged_in"):
        return redirect(
            url_for("login", next=request.url)
        )

    return None


def is_safe_redirect_target(target):
    if not target:
        return False

    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))

    return (
        redirect_url.scheme in ("http", "https")
        and host_url.netloc == redirect_url.netloc
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        username_ok = hmac.compare_digest(
            username.encode("utf-8"),
            ADMIN_USERNAME.encode("utf-8")
        )
        password_ok = hmac.compare_digest(
            password.encode("utf-8"),
            ADMIN_PASSWORD.encode("utf-8")
        )

        if username_ok and password_ok:
            session.clear()
            session["admin_logged_in"] = True
            session.permanent = True

            next_url = request.args.get("next")

            if is_safe_redirect_target(next_url):
                return redirect(next_url)

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ==========================================
# DATABASE
# ==========================================

def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_db():
    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                resort TEXT,
                email TEXT UNIQUE,
                review_status TEXT DEFAULT 'Needs review'
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                campaign_name TEXT,
                subject TEXT,
                body TEXT,
                status TEXT DEFAULT 'Draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS campaign_recipients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
                FOREIGN KEY (contact_id) REFERENCES contacts(id),
                UNIQUE(campaign_id, contact_id)
            )
        """)

        # Contact table migrations
        contact_columns = {
            row["name"] for row in
            conn.execute("PRAGMA table_info(contacts)").fetchall()
        }

        contact_additions = {
            "review_status": "TEXT DEFAULT 'Needs review'",
            "email_consent": "INTEGER DEFAULT 0",
            "unsubscribed": "INTEGER DEFAULT 0"
        }

        for column, definition in contact_additions.items():
            if column not in contact_columns:
                conn.execute(
                    f"ALTER TABLE contacts ADD COLUMN {column} {definition}"
                )

        # Campaign table migrations
        campaign_columns = {
            row["name"] for row in
            conn.execute("PRAGMA table_info(campaigns)").fetchall()
        }

        campaign_additions = {
            "name": "TEXT",
            "campaign_name": "TEXT",
            "subject": "TEXT",
            "body": "TEXT",
            "status": "TEXT DEFAULT 'Draft'",
            "created_at": "TIMESTAMP"
        }

        for column, definition in campaign_additions.items():
            if column not in campaign_columns:
                conn.execute(
                    f"ALTER TABLE campaigns ADD COLUMN {column} {definition}"
                )

        campaign_columns = {
            row["name"] for row in
            conn.execute("PRAGMA table_info(campaigns)").fetchall()
        }

        if "title" in campaign_columns:
            conn.execute("""
                UPDATE campaigns
                SET campaign_name = title
                WHERE (campaign_name IS NULL OR campaign_name = '')
                  AND title IS NOT NULL
            """)

        if "email_subject" in campaign_columns:
            conn.execute("""
                UPDATE campaigns
                SET subject = email_subject
                WHERE (subject IS NULL OR subject = '')
                  AND email_subject IS NOT NULL
            """)

        if "email_message" in campaign_columns:
            conn.execute("""
                UPDATE campaigns
                SET body = email_message
                WHERE (body IS NULL OR body = '')
                  AND email_message IS NOT NULL
            """)

        conn.execute("""
            UPDATE campaigns
            SET campaign_name = name
            WHERE campaign_name IS NULL OR campaign_name = ''
        """)

        conn.execute("""
            UPDATE campaigns
            SET name = campaign_name
            WHERE name IS NULL OR name = ''
        """)

        conn.execute("""
            UPDATE campaigns
            SET campaign_name = 'Untitled campaign'
            WHERE campaign_name IS NULL OR campaign_name = ''
        """)

        conn.execute("""
            UPDATE campaigns SET name = campaign_name
            WHERE name IS NULL OR name = ''
        """)

        conn.execute("""
            UPDATE campaigns SET subject = ''
            WHERE subject IS NULL
        """)

        conn.execute("""
            UPDATE campaigns SET body = ''
            WHERE body IS NULL
        """)

        conn.execute("""
            UPDATE campaigns SET status = 'Draft'
            WHERE status IS NULL OR status = ''
        """)

        conn.execute("""
            UPDATE campaigns SET created_at = CURRENT_TIMESTAMP
            WHERE created_at IS NULL
        """)

        # Delivery history
        conn.execute("""
            CREATE TABLE IF NOT EXISTS delivery_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
                FOREIGN KEY (contact_id) REFERENCES contacts(id)
            )
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# ==========================================
# HELPERS
# ==========================================

def valid_email(email):
    return bool(
        re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email or "")
    )


def personalize_text(template, contact):
    template = template or ""

    replacements = {
        "{{name}}": contact["name"] or "there",
        "{{resort}}": contact["resort"] or "your resort",
        "{{email}}": contact["email"] or ""
    }

    for placeholder, value in replacements.items():
        template = template.replace(placeholder, str(value))

    return template


def get_unsubscribe_url(contact):
    token = unsubscribe_serializer.dumps({
        "contact_id": contact["id"],
        "email": contact["email"]
    })

    return (
        f"{PUBLIC_BASE_URL}"
        f"{url_for('unsubscribe', token=token)}"
    )


def public_url_is_valid():
    if not PUBLIC_BASE_URL:
        return False

    parsed = urlparse(PUBLIC_BASE_URL)

    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
    )


def get_delivery_counts(conn, campaign_id):
    return conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'Sent' THEN 1 ELSE 0 END) AS sent,
            SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN status = 'Skipped' THEN 1 ELSE 0 END) AS skipped
        FROM delivery_logs
        WHERE campaign_id = ?
    """, (campaign_id,)).fetchone()


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():
    conn = get_db()

    total_contacts = conn.execute(
        "SELECT COUNT(*) FROM contacts"
    ).fetchone()[0]

    total_campaigns = conn.execute(
        "SELECT COUNT(*) FROM campaigns"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "index.html",
        total_contacts=total_contacts,
        total_campaigns=total_campaigns
    )


# ==========================================
# CONTACTS
# ==========================================

@app.route("/contacts")
def contacts():
    search = request.args.get("search", "").strip()
    selected_status = request.args.get("status", "").strip()

    conn = get_db()

    sql = "SELECT * FROM contacts WHERE 1=1"
    params = []

    if search:
        sql += """
            AND (
                name LIKE ? OR resort LIKE ? OR email LIKE ?
            )
        """
        term = f"%{search}%"
        params.extend([term, term, term])

    if selected_status:
        sql += " AND review_status = ?"
        params.append(selected_status)

    sql += " ORDER BY id DESC"

    contact_list = conn.execute(sql, params).fetchall()

    total_contacts = conn.execute(
        "SELECT COUNT(*) FROM contacts"
    ).fetchone()[0]

    status_options = conn.execute("""
        SELECT DISTINCT review_status
        FROM contacts
        WHERE review_status IS NOT NULL
        AND review_status != ''
        ORDER BY review_status
    """).fetchall()

    conn.close()

    return render_template(
        "contacts.html",
        contacts=contact_list,
        search=search,
        selected_status=selected_status,
        status_options=status_options,
        total_contacts=total_contacts
    )


# ==========================================
# ADD CONTACT
# ==========================================

@app.route("/contacts/add", methods=["POST"])
def add_contact():
    name = request.form.get("name", "").strip()
    resort = request.form.get("resort", "").strip()
    email = request.form.get("email", "").strip().lower()

    if not name or not resort or not email:
        flash("Please fill in all contact details.", "error")
        return redirect(url_for("contacts"))

    if not valid_email(email):
        flash("Please enter a valid email address.", "error")
        return redirect(url_for("contacts"))

    conn = get_db()

    try:
        existing = conn.execute("""
            SELECT id FROM contacts
            WHERE LOWER(email) = LOWER(?)
        """, (email,)).fetchone()

        if existing:
            flash("This email address already exists.", "error")
            return redirect(url_for("contacts"))

        conn.execute("""
            INSERT INTO contacts
            (name, resort, email, review_status,
             email_consent, unsubscribed)
            VALUES (?, ?, ?, 'Needs review', 0, 0)
        """, (name, resort, email))

        conn.commit()
        flash("Contact added successfully!", "success")

    except sqlite3.IntegrityError:
        conn.rollback()
        flash("This contact already exists.", "error")

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Manual contact creation failed")
        flash("Could not save the contact. Please try again.", "error")

    finally:
        conn.close()

    return redirect(url_for("contacts"))


# ==========================================
# UPDATE EMAIL PERMISSION
# ==========================================

@app.route(
    "/contacts/<int:contact_id>/email-permission",
    methods=["POST"]
)
def update_email_permission(contact_id):
    permission = request.form.get("permission")

    if permission not in ("0", "1"):
        flash("Invalid permission setting.", "error")
        return redirect(url_for("contacts"))

    conn = get_db()

    contact = conn.execute(
        "SELECT * FROM contacts WHERE id = ?",
        (contact_id,)
    ).fetchone()

    if contact is None:
        conn.close()
        flash("Contact not found.", "error")
        return redirect(url_for("contacts"))

    if permission == "1":
        conn.execute("""
            UPDATE contacts
            SET email_consent = 1,
                review_status = 'Approved'
            WHERE id = ?
        """, (contact_id,))

        flash(
            "Permission marked as approved. "
            "Only do this after verifying permission to email.",
            "success"
        )
    else:
        conn.execute("""
            UPDATE contacts
            SET email_consent = 0
            WHERE id = ?
        """, (contact_id,))

        flash("Email permission disabled.", "success")

    conn.commit()
    conn.close()

    return redirect(url_for("contacts"))


# ==========================================
# IMPORT CONTACTS
# ==========================================

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("Please select a file.", "error")
        return redirect(url_for("contacts"))

    file = request.files["file"]

    if file.filename == "":
        flash("Please select a file.", "error")
        return redirect(url_for("contacts"))

    conn = None

    try:
        if file.filename.lower().endswith(".csv"):
            df = pd.read_csv(file)
        elif file.filename.lower().endswith(".xlsx"):
            df = pd.read_excel(file)
        else:
            flash("Only CSV and XLSX files are supported.", "error")
            return redirect(url_for("contacts"))

        df.columns = [
            str(col).strip().lower().replace(" ", "_")
            for col in df.columns
        ]

        aliases = {
            "name": ["name", "owner_name", "contact_name"],
            "resort": ["resort", "resort_name", "hotel", "hotel_name"],
            "email": ["email", "email_address", "mail"]
        }

        column_map = {}

        for field, possible_names in aliases.items():
            for possible_name in possible_names:
                if possible_name in df.columns:
                    column_map[field] = possible_name
                    break

        if not all(
            field in column_map
            for field in ("name", "resort", "email")
        ):
            flash(
                "Your file must contain Name, Resort and Email columns.",
                "error"
            )
            return redirect(url_for("contacts"))

        conn = get_db()
        added = 0
        skipped = 0

        for _, row in df.iterrows():
            raw_name = row[column_map["name"]]
            raw_resort = row[column_map["resort"]]
            raw_email = row[column_map["email"]]

            name = "" if pd.isna(raw_name) else str(raw_name).strip()
            resort = "" if pd.isna(raw_resort) else str(raw_resort).strip()
            email = (
                "" if pd.isna(raw_email)
                else str(raw_email).strip().lower()
            )

            if not email or not valid_email(email):
                skipped += 1
                continue

            try:
                conn.execute("""
                    INSERT INTO contacts
                    (name, resort, email, review_status,
                     email_consent, unsubscribed)
                    VALUES (?, ?, ?, 'Needs review', 0, 0)
                """, (name, resort, email))
                added += 1

            except sqlite3.IntegrityError:
                skipped += 1

        conn.commit()

        flash(
            f"{added} contacts imported. {skipped} skipped "
            "(invalid or duplicate). New contacts are not approved.",
            "success"
        )

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Contact import failed")
        flash("Import failed. Check the file format and columns.", "error")

    finally:
        if conn:
            conn.close()

    return redirect(url_for("contacts"))


# ==========================================
# DELETE CONTACT
# ==========================================

@app.route("/contacts/delete/<int:contact_id>", methods=["POST"])
def delete_contact(contact_id):
    conn = get_db()

    conn.execute(
        "DELETE FROM campaign_recipients WHERE contact_id = ?",
        (contact_id,)
    )

    conn.execute(
        "DELETE FROM delivery_logs WHERE contact_id = ?",
        (contact_id,)
    )

    conn.execute(
        "DELETE FROM contacts WHERE id = ?",
        (contact_id,)
    )

    conn.commit()
    conn.close()

    flash("Contact deleted successfully.", "success")
    return redirect(url_for("contacts"))


# ==========================================
# CAMPAIGNS PAGE
# ==========================================

@app.route("/campaigns")
def campaigns():
    conn = get_db()

    contact_list = conn.execute("""
        SELECT *
        FROM contacts
        ORDER BY resort ASC
    """).fetchall()

    campaign_list = conn.execute("""
        SELECT
            campaigns.*,
            COUNT(campaign_recipients.id) AS recipient_count
        FROM campaigns
        LEFT JOIN campaign_recipients
            ON campaigns.id = campaign_recipients.campaign_id
        GROUP BY campaigns.id
        ORDER BY campaigns.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "campaigns.html",
        contacts=contact_list,
        campaigns=campaign_list
    )


# ==========================================
# CAMPAIGN PREVIEW
# ==========================================

@app.route("/campaigns/<int:campaign_id>/preview")
def campaign_preview(campaign_id):
    conn = get_db()

    campaign = conn.execute("""
        SELECT * FROM campaigns WHERE id = ?
    """, (campaign_id,)).fetchone()

    if campaign is None:
        conn.close()
        flash("Campaign not found.", "error")
        return redirect(url_for("campaigns"))

    recipients = conn.execute("""
        SELECT contacts.*
        FROM campaign_recipients
        JOIN contacts
            ON campaign_recipients.contact_id = contacts.id
        WHERE campaign_recipients.campaign_id = ?
        ORDER BY contacts.resort ASC
    """, (campaign_id,)).fetchall()

    eligible_count = conn.execute("""
        SELECT COUNT(*)
        FROM campaign_recipients cr
        JOIN contacts c ON c.id = cr.contact_id
        WHERE cr.campaign_id = ?
          AND c.email_consent = 1
          AND c.unsubscribed = 0
          AND c.review_status = 'Approved'
    """, (campaign_id,)).fetchone()[0]

    delivery_counts = get_delivery_counts(conn, campaign_id)

    conn.close()

    previews = []

    for contact in recipients:
        previews.append({
            "name": contact["name"],
            "resort": contact["resort"],
            "email": contact["email"],
            "subject": personalize_text(campaign["subject"], contact),
            "body": personalize_text(campaign["body"], contact),
            "approved": (
                contact["email_consent"] == 1
                and contact["unsubscribed"] == 0
                and contact["review_status"] == "Approved"
            ),
            "unsubscribed": contact["unsubscribed"]
        })

    return render_template(
        "campaign_preview.html",
        campaign=campaign,
        previews=previews,
        eligible_count=eligible_count,
        delivery_counts=delivery_counts,
        public_url_ready=public_url_is_valid()
    )


# ==========================================
# CREATE CAMPAIGN
# ==========================================

@app.route("/campaigns/create", methods=["POST"])
def create_campaign():
    campaign_name = request.form.get(
        "campaign_name", ""
    ).strip()

    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    selected_contacts = request.form.getlist("recipients")

    if not campaign_name or not subject or not body:
        flash("Please complete all campaign fields.", "error")
        return redirect(url_for("campaigns"))

    if not selected_contacts:
        flash("Please select at least one recipient.", "error")
        return redirect(url_for("campaigns"))

    conn = get_db()

    try:
        cursor = conn.execute("""
            INSERT INTO campaigns
            (name, campaign_name, subject, body, status)
            VALUES (?, ?, ?, ?, 'Draft')
        """, (campaign_name, campaign_name, subject, body))

        campaign_id = cursor.lastrowid
        added_recipients = 0

        for raw_contact_id in selected_contacts:
            try:
                contact_id = int(raw_contact_id)
            except (TypeError, ValueError):
                continue

            result = conn.execute("""
                INSERT OR IGNORE INTO campaign_recipients
                (campaign_id, contact_id)
                SELECT ?, id FROM contacts WHERE id = ?
            """, (campaign_id, contact_id))

            added_recipients += result.rowcount

        if added_recipients == 0:
            conn.rollback()
            flash("No valid recipients selected.", "error")
            return redirect(url_for("campaigns"))

        conn.commit()

        flash(
            f"Campaign saved as a draft with "
            f"{added_recipients} recipient(s).",
            "success"
        )

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Campaign creation failed")
        flash("Could not save the campaign.", "error")

    finally:
        conn.close()

    return redirect(url_for("campaigns"))


# ==========================================
# SEND CAMPAIGN
# ==========================================

@app.route("/campaigns/<int:campaign_id>/send", methods=["POST"])
def send_campaign(campaign_id):

    if request.form.get("confirm_send") != "yes":
        flash("Please confirm before sending.", "error")
        return redirect(
            url_for("campaign_preview", campaign_id=campaign_id)
        )

    if not public_url_is_valid():
        flash(
            "Sending is disabled. Configure a public HTTPS "
            "unsubscribe URL first.",
            "error"
        )
        return redirect(
            url_for("campaign_preview", campaign_id=campaign_id)
        )

    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        flash("SMTP credentials are missing.", "error")
        return redirect(
            url_for("campaign_preview", campaign_id=campaign_id)
        )

    conn = get_db()

    campaign = conn.execute("""
        SELECT * FROM campaigns WHERE id = ?
    """, (campaign_id,)).fetchone()

    if campaign is None:
        conn.close()
        flash("Campaign not found.", "error")
        return redirect(url_for("campaigns"))

    recipients = conn.execute("""
        SELECT c.*
        FROM campaign_recipients cr
        JOIN contacts c ON c.id = cr.contact_id
        WHERE cr.campaign_id = ?
        ORDER BY c.id
    """, (campaign_id,)).fetchall()

    if not recipients:
        conn.close()
        flash("This campaign has no recipients.", "error")
        return redirect(url_for("campaigns"))

    already_sent = conn.execute("""
        SELECT COUNT(*)
        FROM delivery_logs
        WHERE campaign_id = ? AND status = 'Sent'
    """, (campaign_id,)).fetchone()[0]

    if already_sent:
        conn.close()
        flash(
            "This campaign already has successful deliveries. "
            "Create a new campaign for a new send.",
            "error"
        )
        return redirect(
            url_for("campaign_preview", campaign_id=campaign_id)
        )

    sent = 0
    failed = 0
    skipped = 0

    try:
        for index, contact in enumerate(recipients):

            previous = conn.execute("""
                SELECT id FROM delivery_logs
                WHERE campaign_id = ?
                  AND contact_id = ?
                  AND status = 'Sent'
                LIMIT 1
            """, (campaign_id, contact["id"])).fetchone()

            if previous:
                skipped += 1
                continue

            if (
                contact["email_consent"] != 1
                or contact["unsubscribed"] == 1
                or contact["review_status"] != "Approved"
            ):
                conn.execute("""
                    INSERT INTO delivery_logs
                    (campaign_id, contact_id, status, error_message)
                    VALUES (?, ?, 'Skipped', ?)
                """, (
                    campaign_id,
                    contact["id"],
                    "No verified email permission or contact is unsubscribed."
                ))
                conn.commit()
                skipped += 1
                continue

            if not valid_email(contact["email"]):
                conn.execute("""
                    INSERT INTO delivery_logs
                    (campaign_id, contact_id, status, error_message)
                    VALUES (?, ?, 'Failed', ?)
                """, (
                    campaign_id,
                    contact["id"],
                    "Invalid email address."
                ))
                conn.commit()
                failed += 1
                continue

            try:
                subject = personalize_text(
                    campaign["subject"], contact
                )
                body = personalize_text(
                    campaign["body"], contact
                )

                unsubscribe_url = get_unsubscribe_url(contact)

                body += (
                    "\n\n------------------------------\n"
                    "You are receiving this email because "
                    "you agreed to receive communication from TREC.\n"
                    "To stop receiving these emails, unsubscribe here:\n"
                    f"{unsubscribe_url}\n"
                )

                message = Message(
                    subject=subject,
                    recipients=[contact["email"]],
                    body=body
                )

                mail.send(message)

                conn.execute("""
                    INSERT INTO delivery_logs
                    (campaign_id, contact_id, status)
                    VALUES (?, ?, 'Sent')
                """, (campaign_id, contact["id"]))

                conn.commit()
                sent += 1

            except Exception:
                app.logger.exception(
                    "Campaign delivery failed for contact %s",
                    contact["id"]
                )

                conn.execute("""
                    INSERT INTO delivery_logs
                    (campaign_id, contact_id, status, error_message)
                    VALUES (?, ?, 'Failed', ?)
                """, (
                    campaign_id,
                    contact["id"],
                    "SMTP delivery failed. Check the application log."
                ))

                conn.commit()
                failed += 1

            if index < len(recipients) - 1:
                time.sleep(SEND_DELAY_SECONDS)

        if sent and failed == 0 and skipped == 0:
            campaign_status = "Sent"
        elif sent:
            campaign_status = "Partially sent"
        elif failed:
            campaign_status = "Failed"
        else:
            campaign_status = "Not sent"

        conn.execute("""
            UPDATE campaigns
            SET status = ?
            WHERE id = ?
        """, (campaign_status, campaign_id))

        conn.commit()

    finally:
        conn.close()

    flash(
        f"Campaign processing finished. "
        f"Sent: {sent}, Failed: {failed}, Skipped: {skipped}.",
        "success" if sent else "error"
    )

    return redirect(
        url_for("campaign_history", campaign_id=campaign_id)
    )


# ==========================================
# CAMPAIGN DELIVERY HISTORY
# ==========================================

@app.route("/campaigns/<int:campaign_id>/history")
def campaign_history(campaign_id):
    conn = get_db()

    campaign = conn.execute("""
        SELECT * FROM campaigns WHERE id = ?
    """, (campaign_id,)).fetchone()

    if campaign is None:
        conn.close()
        flash("Campaign not found.", "error")
        return redirect(url_for("campaigns"))

    logs = conn.execute("""
        SELECT
            delivery_logs.*,
            contacts.name,
            contacts.resort,
            contacts.email
        FROM delivery_logs
        JOIN contacts ON contacts.id = delivery_logs.contact_id
        WHERE delivery_logs.campaign_id = ?
        ORDER BY delivery_logs.id DESC
    """, (campaign_id,)).fetchall()

    counts = get_delivery_counts(conn, campaign_id)

    conn.close()

    return render_template(
        "campaign_history.html",
        campaign=campaign,
        logs=logs,
        counts=counts
    )


# ==========================================
# UNSUBSCRIBE
# ==========================================

@app.route("/unsubscribe/<token>", methods=["GET", "POST"])
def unsubscribe(token):
    try:
        data = unsubscribe_serializer.loads(
            token,
            max_age=60 * 60 * 24 * 180
        )

    except (BadSignature, SignatureExpired):
        return render_template(
            "unsubscribe.html",
            message="This unsubscribe link is invalid or expired.",
            show_confirmation=False
        )

    if not isinstance(data, dict):
        return render_template(
            "unsubscribe.html",
            message="This unsubscribe link is invalid.",
            show_confirmation=False
        )

    contact_id = data.get("contact_id")
    email = data.get("email")

    if not isinstance(contact_id, int) or not isinstance(email, str):
        return render_template(
            "unsubscribe.html",
            message="This unsubscribe link is invalid.",
            show_confirmation=False
        )

    conn = get_db()

    contact = conn.execute("""
        SELECT * FROM contacts
        WHERE id = ? AND email = ?
    """, (contact_id, email)).fetchone()

    if contact is None:
        conn.close()
        return render_template(
            "unsubscribe.html",
            message="We could not find this contact.",
            show_confirmation=False
        )

    if request.method == "POST":
        conn.execute("""
            UPDATE contacts
            SET unsubscribed = 1,
                email_consent = 0
            WHERE id = ?
        """, (contact["id"],))

        conn.commit()
        conn.close()

        return render_template(
            "unsubscribe.html",
            message="You have been unsubscribed from TREC marketing emails.",
            show_confirmation=False
        )

    conn.close()

    return render_template(
        "unsubscribe.html",
        message="Would you like to unsubscribe from TREC marketing emails?",
        show_confirmation=True,
        token=token
    )


# ==========================================
# SMTP TEST
# ==========================================

@app.route("/smtp-test", methods=["GET", "POST"])
def smtp_test():
    if request.method == "POST":
        recipient = request.form.get("recipient", "").strip()

        if not valid_email(recipient):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("smtp_test"))

        if (
            not app.config["MAIL_USERNAME"]
            or not app.config["MAIL_PASSWORD"]
        ):
            flash("SMTP username or password is missing.", "error")
            return redirect(url_for("smtp_test"))

        try:
            message = Message(
                subject="TREC-Mailer SMTP Test",
                recipients=[recipient],
                body=(
                    "Hello!\n\n"
                    "This is a test email from TREC-Mailer.\n"
                    "Your SMTP integration is working.\n\n"
                    "TREC Team"
                )
            )

            mail.send(message)
            flash("Test email sent successfully!", "success")

        except Exception:
            app.logger.exception("SMTP test failed")
            flash(
                "Email could not be sent. Check SMTP settings.",
                "error"
            )

        return redirect(url_for("smtp_test"))

    return render_template("smtp_test.html")


# ==========================================
# INITIALIZE DATABASE FOR LOCAL AND GUNICORN
# ==========================================

initialize_db()


# ==========================================
# RUN APPLICATION LOCALLY
# ==========================================

if __name__ == "__main__":
    print("TREC-Mailer starting...")
    print("Database initialized.")

    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", 5000)),
        debug=False,
        use_reloader=False
    )
