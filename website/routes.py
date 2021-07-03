from flask import render_template, url_for, flash, redirect, request
from flask_login import login_required, login_user, logout_user, current_user

from website import app, db, bcrypt
from website.forms import RegistrationForm, LoginForm, CaptureForm
from website.models import User, Capture
#from website import settings

 

#alle nicht existenten URLs zur basisseite routen
@app.route("/<path:path>")
@app.route("/")
def home(path=""):
    return render_template("home.html", title="Home")

@app.route("/help")
def help():
    return "Help"


@app.route("/register", methods=["GET", "POST"])
def register():
    #redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = RegistrationForm();
    if form.validate_on_submit():
        hashed_passw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user = User(username=form.username.data, password=hashed_passw)
        db.session.add(user)
        db.session.commit()

        flash(f"Your account has been created! You can log in now.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    #redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            #this sets current_user to user, so we can access all attributes defined in User
            login_user(user, remember=form.remember.data)
            flash("You are logged in!", "success")

            #if user tried to access a special page before authenticating, redirect there
            next_page = request.args.get("next")
            if next_page:
                return redirect(next_page)
            return redirect(url_for("home"))
        else:
            flash("Login failed! Please check your username and password!", "danger")
    return render_template("login.html", title="Login", form=form)


@app.route("/secret")
@login_required
def secret():
    return "secret unlocked"

@app.route("/logout")
def logout():
    logout_user()
    flash("Du bist jetzt ausgeloggt!", category="success")
    return redirect(url_for("home"))


@app.route("/addCapture", methods=["GET", "POST"])
def add_capture():
    form = CaptureForm()
    if form.validate_on_submit():
        flash(f"Capture started ...", "success")
        return redirect(url_for("home"))
    return render_template("add_capture.html", title="Add Capture", form=form)
