import os

from flask import Flask, flash, redirect, render_template, request, session, send_file
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from tempfile import TemporaryDirectory
from os.path import join
from shutil import move
from datetime import datetime
from io import BytesIO
from pathlib import Path
from cryptography.fernet import InvalidToken
import binascii

from encrypt import encrypt_string, decrypt_string
from helpers import apology, login_required, allowed_file

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
HEADER_SEQUENCE = "####126".encode("ascii")


# Configure application
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///uploads.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

db = SQLAlchemy(app)
Session(app)


class InvalidDataLength(HTTPException):
    code = 400


class Users(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(24), unique=True)
    password = db.Column(db.String(255))

    def __init__(self, username, password) -> None:
        if len(username) > 24:
            raise InvalidDataLength("Invalid username length.")
        self.username = username
        if len(password) > 255:
            raise InvalidDataLength("Invalid password length.")
        self.password = password


class Tasks(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    time = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    file = db.Column(db.String(255))

    def __init__(self, user_id, file) -> None:
        self.user_id = user_id
        self.file = file


@app.after_request
def after_request(response):
    """Ensure responses aren't cached."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Homepage of IMGCrypt"""

    user = Users.query.filter_by(id=session["user_id"]).first()
    uploads = Tasks.query.filter_by(user_id=user.id).count()
    totaluploads = Tasks.query.filter_by().count()

    return render_template(
        "home.j2", user=user, uploads=uploads, totaluploads=totaluploads, home=True
    )


@app.route("/tasks")
@login_required
def tasks():
    """Display user uploaded tasks"""

    page = request.args.get("page", 1, int)
    rows = request.args.get("rows", 10, int)

    user = Users.query.filter_by(id=session["user_id"]).first()
    pagination = Tasks.query.filter_by(user_id=user.id).paginate(
        page=page, per_page=rows, count=True, error_out=False
    )
    return render_template(
        "tasks.j2", user=user, tasks=pagination.items, pagination=pagination
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")
        if not username:
            return apology("login.j2", "Must provide username", 400)

        if not password:
            return apology("login.j2", "Must provide password", 400)

        # Query database for username
        user = Users.query.filter_by(username=username).first()

        if not user:
            return apology("login.j2", "User does not exist.", 400)

        # Ensure username exists and password is correct
        if not check_password_hash(user.password, password):
            return apology("login.j2", "Invalid password.", 400)

        # Remember which user has logged in
        session["user_id"] = user.id

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.j2")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not username:
            return apology("register.j2", "Must provide username", 400)

        if not password:
            return apology("register.j2", "Must provide password", 400)

        # Ensure confirmation password matches
        if confirmation != password:
            return apology("register.j2", "Passwords don't match", 400)

        # Check username is unique
        user = Users.query.filter_by(username=username).first()

        if user:
            return apology("register.j2", "User already exists", 400)

        newuser = Users(username, generate_password_hash(password))

        # Insert new user into database
        db.session.add(newuser)
        db.session.commit()

        # Login the user
        session["user_id"] = newuser.id

        flash("User created")
        return redirect("/")

    else:
        return render_template("register.j2")


@app.route("/logout")
def logout():
    """Log user out"""

    # Clear session
    session.clear()

    # Redirect home
    return redirect("/")


@app.route("/encrypt")
@login_required
def encrypt():
    """Show encrypt files template."""
    return render_template("encrypt.j2")


@app.route("/decrypt")
@login_required
def decrypt():
    """Show decrypt files template."""
    return render_template("decrypt.j2")


@app.route("/download/<id>")
@login_required
def download(id: int):
    """Download user uploaded file."""

    task = Tasks.query.filter_by(id=id).first()

    if not task:
        return "Not found", 404

    if task.user_id != session["user_id"]:
        return "Unauthorized", 401

    return send_file(
        f"instance/uploads/{id}",
        download_name=f"encrypted-{task.file}",
        as_attachment=True,
    )


@app.route("/api/decrypt", methods=["POST"])
@login_required
def decryptapi():
    """Decrypt API."""
    if "file" not in request.files:
        return "No file part", 400

    password = request.form.get("password")

    if not password:
        return "Invalid password", 400

    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400

    if not file or not allowed_file(file.filename):
        return "Invalid file", 400

    data = file.stream.read()

    try:
        binary = data.split(HEADER_SEQUENCE)[1:]
        data = binary[2]
        salt = binary[1].decode("ascii")
        name = binary[0].decode("ascii")
    except IndexError:
        return "Invalid encrypted data", 400
    except ValueError:
        return "Invalid encrypted data", 400

    if not data:
        return "No encrypted data", 400

    # Decrypt data
    try:
        decrypted = decrypt_string(password, salt, data)
    except InvalidToken:
        return "Invalid password", 400
    except binascii.Error:
        return "Invalid encrypted data", 400

    return send_file(BytesIO(decrypted), download_name=f"decrypted-{name}")


@app.route("/api/encrypt", methods=["POST"])
@login_required
def encryptapi():
    """File upload encrypt API."""
    if "file" not in request.files:
        return "No file part", 400
    if "data" not in request.files:
        return "No data part", 400

    password = request.form.get("password")

    if not password:
        return "Invalid password", 400

    file = request.files["file"]
    data = request.files["data"]
    if file.filename == "":
        return "No selected file", 400

    if not file or not allowed_file(file.filename):
        return "Invalid file", 400

    filename = secure_filename(file.filename)  # type: ignore
    dataname = secure_filename(data.filename)  # type: ignore
    # Create temp dir for file
    with TemporaryDirectory() as tmp:
        path = join(tmp, filename)
        file.save(path)

        with open(path, "ab") as file:
            bytes, salt = encrypt_string(password, data.stream.read())
            file.write(HEADER_SEQUENCE)
            file.write(dataname.encode("ascii"))
            file.write(HEADER_SEQUENCE)
            file.write(salt)
            file.write(HEADER_SEQUENCE)
            file.write(bytes)

        # https://stackoverflow.com/questions/57513335/python-read-file-by-bytes-until-sequence-of-bytes
        with open(path, "rb") as file:
            lines = file.readlines()
            combined_line = b"".join(lines)
            try:
                splitted = combined_line.split(HEADER_SEQUENCE)[1:]
                salted = splitted[1]
                data = splitted[2]
                if data != bytes:
                    return "Error encrypting data", 400
                if salted != salt:
                    return "Error writting salt", 400
                if splitted[0].decode("ascii") != dataname:
                    return "Error encrypting file name", 400
            except ValueError:
                return "Invalid encrypted data", 400

        # Create task
        task = Tasks(session["user_id"], filename)

        # Insert task into database
        db.session.add(task)
        db.session.commit()

        Path("instance/uploads").mkdir(parents=True, exist_ok=True)
        move(path, join(SCRIPT_DIR, f"instance/uploads/{task.id}"))
        return str(task.id)


@app.route("/changepwd", methods=["GET", "POST"])
@login_required
def changepwd():
    """Change user password."""

    if request.method == "POST":

        oldpassword = request.form.get("oldpassword")
        newpassword = request.form.get("newpassword")
        confirmpassword = request.form.get("confirmpassword")

        # Ensure passwords were submitted
        if not oldpassword:
            return apology("changepwd.j2", "Must provide old password", 400)

        elif not newpassword:
            return apology("changepwd.j2", "Must provide password", 400)

        # Ensure passwords match
        elif newpassword != confirmpassword:
            return apology("changepwd.j2", "Passwords don't match", 400)

        # Get user from database
        user = Users.query.filter_by(id=session["user_id"]).first()

        # Invalid session id
        if not user:
            return apology("changepwd.j2", "Invalid user", 400)

        # Ensure old password is valid
        if not check_password_hash(user.password, oldpassword):
            return apology("changepwd.j2", "Wrong password", 401)

        user.password = generate_password_hash(newpassword)

        # Apply to database
        db.session.commit()

        # Redirect user to home page
        flash("Password changed")
        return redirect("/")

    else:
        return render_template("changepwd.j2")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
