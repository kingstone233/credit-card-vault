import os
import hashlib
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# ------------------------------------------------------------
# Database connection
# ------------------------------------------------------------
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:ULSoPFbWtFLKdfGSfxWRABbXUCKEcqeO@tramway.proxy.rlwy.net:42013/railway"
)

# AES key used with pgcrypto's encrypt()/decrypt() - keep this OUT of source
# control in a real deployment; here it's read from an env var with a dev fallback.
AES_KEY = os.environ.get("AES_KEY", "dev-only-change-this-key-32chars")


def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def hash_password(password: str) -> str:
    """SHA-256 hash (SHA-2 family) of the password, stored as hex string."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------
def login_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


def roles_required(*allowed_roles):
    from functools import wraps

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                flash("You do not have permission to access that page.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)

        return wrapper

    return decorator


# ------------------------------------------------------------
# ROUTES: Auth
# ------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT user_id, username, password_hash, role FROM users WHERE username = %s",
            (username,),
        )
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and user["password_hash"] == hash_password(password):
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome, {user['username']} ({user['role']}).", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
@roles_required("admin")
def register():
    """Admin-only: create new application users with a chosen role."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        if role not in ("admin", "support", "billing"):
            flash("Invalid role selected.", "error")
            return redirect(url_for("register"))

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                (username, hash_password(password), role),
            )
            conn.commit()
            flash(f"User '{username}' created with role '{role}'.", "success")
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash("That username already exists.", "error")
        finally:
            cur.close()
            conn.close()
        return redirect(url_for("register"))

    return render_template("register.html")


# ------------------------------------------------------------
# ROUTES: Dashboard
# ------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", role=session.get("role"), username=session.get("username"))


# ------------------------------------------------------------
# ROUTES: Customers (support + admin)
# ------------------------------------------------------------
@app.route("/customers", methods=["GET"])
@roles_required("admin", "support")
def list_customers():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM support_customers ORDER BY customer_id DESC")
    customers = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("customers.html", customers=customers)


@app.route("/customers/new", methods=["GET", "POST"])
@roles_required("admin", "support")
def new_customer():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                """INSERT INTO customers (full_name, email, phone, address)
                   VALUES (%s, %s, %s, %s)""",
                (full_name, email, phone, address),
            )
            conn.commit()
            flash("Customer added successfully.", "success")
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash("A customer with that email already exists.", "error")
        finally:
            cur.close()
            conn.close()
        return redirect(url_for("list_customers"))

    return render_template("customer_form.html")


# ------------------------------------------------------------
# ROUTES: Cards (billing + admin) - sensitive data, AES encrypted
# ------------------------------------------------------------
@app.route("/cards", methods=["GET"])
@roles_required("admin", "billing")
def list_cards():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM billing_cards ORDER BY card_id DESC")
    cards = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("cards.html", cards=cards)


@app.route("/cards/new", methods=["GET", "POST"])
@roles_required("admin", "billing")
def new_card():
    if request.method == "POST":
        customer_id = request.form.get("customer_id", "")
        card_type = request.form.get("card_type", "").strip()
        card_number = request.form.get("card_number", "").strip().replace(" ", "")
        cvv = request.form.get("cvv", "").strip()
        expiry_date = request.form.get("expiry_date", "").strip()  # MM/YYYY

        if len(card_number) < 4:
            flash("Invalid card number.", "error")
            return redirect(url_for("new_card"))

        last_four = card_number[-4:]

        conn = get_db()
        cur = conn.cursor()
        try:
            # pgcrypto AES encryption happens inside PostgreSQL itself -
            # the plaintext card number/cvv never touch disk unencrypted.
            cur.execute(
                """
                INSERT INTO cards
                    (customer_id, card_type, last_four,
                     encrypted_card_number, encrypted_cvv, expiry_date)
                VALUES
                    (%s, %s, %s,
                     encrypt(%s::bytea, %s::bytea, 'aes'),
                     encrypt(%s::bytea, %s::bytea, 'aes'),
                     %s)
                """,
                (
                    customer_id, card_type, last_four,
                    card_number.encode(), AES_KEY.encode(),
                    cvv.encode(), AES_KEY.encode(),
                    expiry_date,
                ),
            )
            conn.commit()
            flash("Card added and encrypted successfully.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error adding card: {e}", "error")
        finally:
            cur.close()
            conn.close()
        return redirect(url_for("list_cards"))

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT customer_id, full_name FROM support_customers ORDER BY full_name")
    customers = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("card_form.html", customers=customers)


@app.route("/cards/<int:card_id>/reveal")
@roles_required("admin")
def reveal_card(card_id):
    """Admin-only: decrypt and view full card number + CVV for a single card."""
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT card_id, card_type, last_four, expiry_date,
               convert_from(decrypt(encrypted_card_number, %s::bytea, 'aes'), 'UTF8') AS card_number,
               convert_from(decrypt(encrypted_cvv, %s::bytea, 'aes'), 'UTF8') AS cvv
        FROM cards WHERE card_id = %s
        """,
        (AES_KEY.encode(), AES_KEY.encode(), card_id),
    )
    card = cur.fetchone()
    cur.close()
    conn.close()
    if not card:
        flash("Card not found.", "error")
        return redirect(url_for("list_cards"))
    return render_template("card_reveal.html", card=card)


# ------------------------------------------------------------
# ROUTES: Invoices (billing + admin insert, everyone logged-in can view)
# ------------------------------------------------------------
@app.route("/invoices", methods=["GET"])
@login_required
def list_invoices():
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM public_invoices ORDER BY invoice_id DESC")
    invoices = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("invoices.html", invoices=invoices)


@app.route("/invoices/new", methods=["GET", "POST"])
@roles_required("admin", "billing")
def new_invoice():
    if request.method == "POST":
        customer_id = request.form.get("customer_id", "")
        card_id = request.form.get("card_id", "")
        invoice_date = request.form.get("invoice_date", "")
        amount = request.form.get("amount", "")
        description = request.form.get("description", "").strip()

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute(
                """INSERT INTO invoices (customer_id, card_id, invoice_date, amount, description)
                   VALUES (%s, %s, %s, %s, %s)""",
                (customer_id, card_id, invoice_date, amount, description),
            )
            conn.commit()
            flash("Invoice created successfully.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Error creating invoice: {e}", "error")
        finally:
            cur.close()
            conn.close()
        return redirect(url_for("list_invoices"))

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT customer_id, full_name FROM support_customers ORDER BY full_name")
    customers = cur.fetchall()
    cur.execute("SELECT card_id, customer_id, last_four FROM billing_cards ORDER BY card_id")
    cards = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("invoice_form.html", customers=customers, cards=cards)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)