from tempfile import tempdir
from flask import render_template, url_for, flash, redirect, request, jsonify, send_from_directory
from flask_login import login_required, login_user, logout_user, current_user

from website import app, db, bcrypt
from website.forms import RegistrationForm, LoginForm, CaptureForm
from website.models import User, Capture
from website.settings import INTERFACE

from website.hw import get_capture, start_capture, stop_capture, get_running_ids
from website.aps import start_scan, stop_scan, get_aps
import website.gps as gps

from sqlalchemy import desc
import secrets
import random
import os, shutil
import json
from scapy.all import *

 

#alle nicht existenten URLs zur basisseite routen
@app.route("/<path:path>")
@app.route("/")
@login_required
def home(path=""):
    running_ids = get_running_ids()
    running_ids.sort()
    running_captures = Capture.query.filter(Capture.id.in_(running_ids)).all()
    old_captures = Capture.query.filter(~Capture.id.in_(running_ids)).order_by(desc(Capture.date_created)).all()
    db.session.commit()
    return render_template("home.html", title="Home", running=running_captures, old = old_captures)

@app.route("/help")
def help():
    return "Help"


@app.route("/register", methods=["GET", "POST"])
def register():
    #redirect if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = RegistrationForm()
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


@app.route("/geo/start")
@login_required
def geo_start():
    gps.start_gps_tracking()
    flash("Started GPS Module", "success")
    return redirect(url_for("geo"))

@app.route("/geo/stop")
@login_required
def geo_stop():
    gps.stop_gps_tracking()
    flash("Stopped GPS Module", "success")
    return redirect(url_for("geo"))

@app.route("/geo")
@login_required
def geo():
    available = gps.is_gps_available()
    lat, lon = gps.get_gps_data()
    return render_template("geo.html", available=available, lat=lat, lon=lon)

@app.route("/capture/<int:id>/start")
@login_required
def capture_start(id):
    title = request.args.get("title")
    if not title:
        title = ""
    try:
        start_capture(id, 11, INTERFACE)
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
        return render_template("capture.html", title="Show Capture", c=c)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("home")) 

@app.route("/capture/<int:id>/download")
def capture_download(id):
    c = Capture.query.get(id)
    if c:
        dir_path = os.path.join(app.root_path, "static", "captures", str(c.id))
        out = os.path.join(dir_path, c.title)
        #shutil.make_archive(out, 'zip', dir_path)
        return send_from_directory(dir_path, "cap.pcap", as_attachment=True, attachment_filename=c.title+".pcap")
    else:
        flash(f"Folder for capture with id {id} not found", "danger")
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
        #add to db
        title = form.title.data
        filename = gen_filename(title)
        cap = Capture(title=form.title.data, desc=form.desc.data, filename=filename, user_id=current_user.id)
        db.session.add(cap)
        db.session.commit()

        #add directory
        path = os.path.join(app.root_path, "static", "captures", str(cap.id))
        os.makedirs(path)

        return redirect(url_for("capture_start", id=cap.id, title=title))
    return render_template("add_capture.html", title="Add Capture", form=form)

@app.route("/capture/<int:id>/delete")
@login_required
def capture_delete(id: int):
    c = Capture.query.get(id)
    if c:
        path = os.path.join(app.root_path, "static", "captures", str(c.id))
        try:
            shutil.rmtree(path)
            db.session.delete(c)
            db.session.commit()
            flash(f"Capture {c.title} was successfully deleted.", "success")
        except OSError as e:
            print(f"Could not delete directory {path}")
    else:
        flash(f"Capture does not exist.", "danger")
    return redirect(url_for("home")) 
    

@app.route("/detect/start")
@login_required
def detect_start():
    try:
        start_scan(INTERFACE)
        flash("Starting Access Point Scan", "success")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("detect_aps")) 

@app.route("/detect/stop")
@login_required
def detect_stop():
    stop_scan()
    flash("Stopped Access Point Scan", "success")
    return redirect(url_for("detect_aps")) 

@app.route("/detect/get")
@login_required
def detect_get():
    aps = get_aps()
    return jsonify(aps=aps)

@app.route("/detect")
@login_required
def detect_aps():
    return render_template("detect.html", title="Detect Access Points")
