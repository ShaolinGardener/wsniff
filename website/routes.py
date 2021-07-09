from tempfile import tempdir
from flask import render_template, url_for, flash, redirect, request, jsonify
from flask_login import login_required, login_user, logout_user, current_user
from scapy.arch.linux import IFF_DEBUG

from website import app, db, bcrypt
from website.forms import RegistrationForm, LoginForm, CaptureForm
from website.models import User, Capture

from website.hw import get_capture, start_capture, stop_capture, get_running_ids

import secrets
import os

 

#alle nicht existenten URLs zur basisseite routen
@app.route("/<path:path>")
@app.route("/")
@login_required
def home(path=""):
    running_ids = get_running_ids()
    running_ids.sort()
    running_captures = Capture.query.filter(Capture.id.in_(running_ids)).all()
    return render_template("home.html", title="Home", running=running_captures)

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


@app.route("/geo")
@login_required
def secret():
    return render_template("geo.html")

@app.route("/capture/<int:id>/start")
@login_required
def capture_start(id):
    title = request.args.get("title")
    if not title:
        title = ""
    try:
        start_capture(id, 11, "en0")
        flash(f"Capture {title} started", "success")
    except ValueError as e:
        flash(f"Capture {title} already running.", "danger")
    return redirect(url_for("home"))

@app.route("/capture/<int:id>/stop")
@login_required
def capture_stop(id):
    title = request.args.get("title")
    if not title:
        title = ""
    try:
        stop_capture(id)
        flash(f"Capture {title} stopped", "success")
    except ValueError as e:
        flash(f"Capture {title} can't be stopped since it does not exist.", "danger")

    return redirect(url_for("home"))

@app.route("/capture/<int:id>")
@login_required
def capture_get(id):
    try:
        c = get_capture(id) 
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("home"))
    
    return jsonify(id=c.id, num_packets=c.num_packets)

@app.route("/capture/<int:id>/show")
def capture_show(id):
    try:
        c = get_capture(id) 
        return render_template("captures.html", title="Show Capture", c=c)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("home")) 


@app.route("/logout")
def logout():
    logout_user()
    flash("Du bist jetzt ausgeloggt!", category="success")
    return redirect(url_for("login"))


def gen_filename(title):
    fn = ""
    while True:
        fn = secrets.token_hex(10) + ".cap"
        #check wether a file with this name already exists
        duplicate = Capture.query.filter_by(filename=fn).first()
        if not duplicate:
            break
    return os.path.join(app.root_path, "static", "captures", fn)



@app.route("/capture/new", methods=["GET", "POST"])
@login_required
def new_capture():
    form = CaptureForm()
    if form.validate_on_submit():
        title = form.title.data
        filename = gen_filename(title)
        cap = Capture(title=form.title.data, desc=form.desc.data, filename=filename, user_id=current_user.id)
        db.session.add(cap)
        db.session.commit()

        return redirect(url_for("capture_start", id=cap.id, title=title))
    return render_template("add_capture.html", title="Add Capture", form=form)
