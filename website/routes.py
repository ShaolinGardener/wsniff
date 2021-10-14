from tempfile import tempdir
from flask import render_template, url_for, flash, redirect, request, jsonify, send_from_directory
from flask_login import login_required, login_user, logout_user, current_user

from website import app, db, bcrypt
from website.forms import RegistrationForm, LoginForm, CaptureAllForm, WardrivingForm, ExternalWiFiForm, ServerConnectionForm, ServerDeviceRegistrationForm
from website.models import User, Capture, CaptureState, CaptureType, Map

import website.capture.capture as capture
from website.capture.behavior import CaptureAllBehavior, MapAccessPointsBehavior, OnlineMapBehavior
import website.aps as aps
from website.aps import start_scan, stop_scan, get_aps
import website.gps as gps
from website.interfaces import Interface, get_interfaces, Mode, monitor_interface_available, get_all_interfaces
import website.oui as oui
from website.settings import WPA_SUPPLICANT_BACKUP_PATH
import website.server as server
import website.api as api

import display.display as display

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
    """
    Route for dashboard with all running and finished captures
    """
    running_ids = capture.get_running_ids()
    running_ids.sort()
    
    running_captures = [c for c in current_user.captures if c.id in running_ids]
    
    old_captures_capture_all = [c for c in current_user.captures if c.id not in running_ids and c.type == CaptureType.CAPTURE_ALL]
    old_captures_capture_all.sort(key= lambda cap: cap.date_created, reverse=True)
    old_captures_wardriving = [c for c in current_user.captures if c.id not in running_ids and c.type == CaptureType.WARDRIVING]
    old_captures_wardriving.sort(key= lambda cap: cap.date_created, reverse=True)

    #following code only made sense before user authetication was implemented
    #running_captures = Capture.query.filter(Capture.id.in_(running_ids)).all()
    #old_captures = Capture.query.filter(~Capture.id.in_(running_ids)).order_by(desc(Capture.date_created)).all()
    #db.session.commit()

    interface_available = monitor_interface_available()
    return render_template("home.html", title="Home", interface_available=interface_available, running=running_captures, old_capture_all=old_captures_capture_all, old_wardriving=old_captures_wardriving)


#############################################USER RELATED#########################################

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Route for user registration
    """
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
    """
    If a user needs authetication, he is redirected to this route.
    """
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


@app.route("/logout")
def logout():
    """
    Logout user
    """
    logout_user()

    flash("You are now logged out!", category="success")
    return redirect(url_for("login"))
    

@app.route("/settings")
@login_required
def settings():
    """
    Display the settings of this device
    """
    managed = get_interfaces(Mode.MANAGED)
    monitor = get_interfaces(Mode.MONITOR)
    gps_running = gps.gps_is_running()
    return render_template("settings.html", title="Settings", managed=managed, monitor=monitor, gps_running=gps_running)

########################################HARDWARE RELATED#########################################

@app.route("/settings/reboot")
def reboot():
    """
    Reboot the device
    """
    #clear temp dir
    temp_dirpath = os.path.join(app.root_path, "static", "tmp", "*")
    subprocess.run("rm " + temp_dirpath, shell=True, check=False) #check=False because it can be empty and then this command will fail

    #shutdown display
    display.shutdown()

    str_shutdown = "reboot"
    subprocess.run(str_shutdown, shell=True, check=True)
    return render_template("settings.html", title="Settings") #should not be executed

@app.route("/settings/shutdown")
def shutdown():
    """
    Shutdown the device
    """
    #clear temp dir
    temp_dirpath = os.path.join(app.root_path, "static", "tmp", "*")
    subprocess.run("rm " + temp_dirpath, shell=True, check=False) #check=False because it can be empty and then this command will fail
    
    #shutdown display
    display.shutdown()

    str_shutdown = "shutdown -h now"
    subprocess.run(str_shutdown, shell=True, check=True)
    return render_template("settings.html", title="Settings") #should not be executed

@app.route("/settings/interfaces/<string:interface>/monitor/activate")
@login_required
def activate_monitor(interface:str):
    """
    Activate the monitor mode for a given interface
    """
    try:
        iface = get_all_interfaces()[interface]
        iface.enable_monitor_mode()
    except:
       flash(f"Could not turn '{interface}' into monitor mode", "danger") 
       return redirect(url_for("settings"))

    flash(f"Interface '{interface}' is now in monitor mode", "success")
    return redirect(url_for("settings"))

@app.route("/settings/interfaces/<string:interface>/monitor/deactivate")
@login_required
def deactivate_monitor(interface:str):
    """
    Return an interface to managed mode
    """
    try:
        iface = get_all_interfaces()[interface]
        iface.disable_monitor_mode()
    except:
       flash(f"Could not disable '{interface}'", "danger") 
       return redirect(url_for("settings"))

    flash(f"Disabled monitor mode for '{interface}'", "success")
    return redirect(url_for("settings"))

@app.route("/settings/oui/update")
@login_required
def update_oui():
    """
    Update the oui information of this device
    """
    oui_dirpath = os.path.join(app.root_path, "static", "res")
    try:
        oui.download(to_directory=oui_dirpath)
        oui.load_local_oui(oui_dirpath)
    except Exception as e:
        flash("Failed to update. Check your internet connection.", "danger")
        return redirect(url_for("settings"))
    
    flash("Successfull update", "success")
    return redirect(url_for("settings"))


########################################GPS SECTION############################################

@app.route("/gps/start")
@login_required
def gps_start():
    """
    Start GPS tracking of the device
    """
    gps.start_gps_tracking()
    flash("Started GPS Module", "success")
    return redirect(url_for("gps_show"))

@app.route("/gps/stop")
@login_required
def gps_stop():
    """
    Stop GPS tracking of the device
    """
    gps.stop_gps_tracking()
    flash("Stopped GPS Module", "success")
    return redirect(url_for("gps_show"))

@app.route("/gps")
@login_required
def gps_show():
    """
    Route for testing gps tracking
    """
    available = gps.is_gps_available()
    lat, lon = gps.get_gps_data()
    running = gps.gps_is_running()
    return render_template("gps.html", available=available, lat=lat, lon=lon, running=running)


#########################################CAPTURE SECTION#########################################

@app.route("/capture/<int:id>/stop")
@login_required
def capture_stop(id):
    """
    Stop a certain capture
    """
    title = request.args.get("title")
    if not title: title = ""
    
    try:
        capture.stop_capture(id)
        c = Capture.query.get(id)
        c.state = CaptureState.COMPLETED
        db.session.commit()
        flash(f"Capture {title} stopped", "success")
    except ValueError as e:
        flash(f"Capture {title} can't be stopped since it does not exist.", "danger")

    return redirect(url_for("home"))

@app.route("/capture/<int:id>")
@login_required
def capture_get(id):
    """
    Get the updated data of a certain capture
    """
    try:
        c = capture.get_capture(id) 
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("home"))
    
    return jsonify(id=c.id, num_packets=c.num_packets)

@app.route("/capture/<int:id>/show")
def capture_show(id):
    """
    Display a certain capture
    """
    try:
        capture = Capture.query.get(id)
        return render_template("capture.html", title="Show Capture", capture=capture)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("home")) 

@app.route("/capture/<int:id>/download")
def capture_download(id):
    """
    Transfer capture data to terminal device (e.g. laptop) by zipping the corresponding data
    """
    c = Capture.query.get(id)
    if c:
        dir_path = os.path.join(app.root_path, "static", "captures", str(c.id))
        
        out_dirpath = os.path.join(app.root_path, "static", "tmp")
        out_filepath = os.path.join(out_dirpath, str(c.id))
        try:
            #first clear tmp directory (you cant delete zip-file after send_from_directory, so this ensures the zip-files don't accumulate)
            subprocess.run("sudo rm " + os.path.join(out_dirpath, "*"), shell=True, check=False) #check=False because if tmp-dir is empty this will fail
            
            #base_name: name of file to create including path but without file ending (.zip)
            #root_dir is a directory that will be the root directory of the archive, all paths in the archive will be relative to it
            #base_dir is the directory where we start archiving from; base_dir must be given relative to root_dir
            shutil.make_archive(base_name=out_filepath, format="zip", root_dir=dir_path, base_dir=".")
            download_filename = (c.title+".zip").replace(" ", "_")
            return send_from_directory(out_dirpath, str(c.id) + ".zip", as_attachment=True, attachment_filename=download_filename)
        except Exception as e:
            flash(f"Error when zipping: {e}", "danger")
    else:
        flash(f"Folder for capture with id {id} not found", "danger")
    return redirect(url_for("home"))

def gen_filename(title):
    """
    Generate unique filename
    """
    fn = ""
    while True:
        fn = secrets.token_hex(10) + ".cap"
        #check wether a file with this name already exists
        duplicate = Capture.query.filter_by(filename=fn).first()
        if not duplicate:
            break
    return os.path.join(app.root_path, "static", "captures", fn)


@app.route("/capture/new/select")
@login_required
def new_capture_selection():
    """
    Show all caputure modes available
    """
    #is an interface with monitor mode available?
    if not monitor_interface_available():
        flash("You have to enable monitor mode for one of your capable interfaces before you can do that.", "danger")
        return redirect(url_for("settings"))

    return render_template("add_capture_overview.html", title="Add Capture")

@app.route("/capture/new", methods=["GET", "POST"])
@login_required
def new_capture():
    """
    Show form to user depending on capture mode
    """
    #is an interface with monitor mode available?
    if not monitor_interface_available():
        flash("You have to enable monitor mode for one of your capable interfaces before you can do that.", "danger")
        return redirect(url_for("settings"))

    try: 
        capture_type = int(request.args.get("capture_type"))
    except:
        pass
    if not capture_type: capture_type = 1

    if capture_type == CaptureType.CAPTURE_ALL:
        capture_type = CaptureType.CAPTURE_ALL
        form = CaptureAllForm()
    elif capture_type == CaptureType.WARDRIVING:
        capture_type = CaptureType.WARDRIVING
        form = WardrivingForm()
    elif capture_type == CaptureType.ONLINE_WARDRIVING:
        capture_type = CaptureType.ONLINE_WARDRIVING
        form = WardrivingForm()
    else: #default 
        raise Exception("[-] This should not be possible because capture_type should have been set to CaptureAll by default")

    if form.validate_on_submit():
        _create_and_start_capture(capture_type, form)
        return redirect(url_for("home"))

    gps_available = gps.is_gps_available()

    return render_template("add_capture.html", title="Add Capture", capture_type=capture_type, form=form, gps_available=gps_available)


def _create_and_start_capture(capture_type: CaptureType, form):
    """
    Actually starts a new capture. Called by new_capture.
    """
    #add to db
    title = form.title.data
    filename = gen_filename(title)
   

    if capture_type == CaptureType.CAPTURE_ALL:
        channel = form.channel.data
        gps_tracking = form.gpsTracking.data
    else:
        channel = None
        gps_tracking = True
    
    #remove channel out of Capture model
    cap = Capture(title=form.title.data, desc=form.desc.data, filename=filename, user_id=current_user.id,
                    gps=gps_tracking, channel=channel, type=capture_type)
    db.session.add(cap)
    db.session.commit()

    #add directory
    path = os.path.join(app.root_path, "static", "captures", str(cap.id))
    os.makedirs(path)

    #create captureBehavior and start capture
    id = cap.id
    #there should be one since we have checked in new_capture
    interface = get_interfaces(Mode.MONITOR)[0]

    if capture_type == CaptureType.CAPTURE_ALL:
        capture_behavior = CaptureAllBehavior(channel, gps_tracking)
    elif capture_type == CaptureType.WARDRIVING:
        capture_behavior = MapAccessPointsBehavior()
    elif capture_type == CaptureType.ONLINE_WARDRIVING:
        title = form.title.data
        desc = form.desc.data
        #try to create map online
        try:
            #create new map on server
            server_map_id = api.create_map(title, description=desc)
            #create local instance of map
            map = Map(title=title, desc=desc, is_online=True, server_map_id=server_map_id)
            try: 
                db.session.add(map)
                db.session.commit()
            except:
                flash("Local map creation failed.", "danger")
                return 
        except:
            flash("Online map creation failed.", "danger")
            return 
        
        #if the map creation on both the server and the local machine worked, 
        #create capture behavior
        capture_behavior = OnlineMapBehavior(map)
    else:
        raise Exception("[-] This should not be possible.")
    
    #actually start capture
    try:
        capture.start_capture(id, interface, capture_behavior)
        cap.state = CaptureState.RUNNING
        db.session.commit()
        flash(f"Capture {title} started", "success")
    except ValueError as e:
        #capture state in DB is FAILED by default when created, so we don't need to set this here
        flash(f"Capture {title} already running.", "danger")
    
    return #attention: this function returns to new_capture


@app.route("/capture/<int:id>/delete")
@login_required
def capture_delete(id: int):
    """
    Delete a capture including its DB entries and files.
    """
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


#WARDRIVE capture
#read data from file
def load_from_file(filepath):
    """
    Load GPS data from file
    """
    f = open(filepath, "r")
    data = list()

    line = f.readline()
    while line:
        t = line.strip().split(";")
        ap = {
            "bssid": t[1],
            "ssid": t[2],
            "channel": t[3],
            "signal_strength": t[4],
            "vendor": t[5],
            "location": [t[6], t[7]]
        }
        data.append(ap)
        line = f.readline()
    f.close()
    return json.dumps(data)

@app.route("/wardrive/<int:id>")
@login_required
def wardrive_capture_show(id):
    """
    Show a wardriving map
    """
    try:
        capture = Capture.query.get(id)
        filepath = os.path.join(app.root_path, "static", "captures", str(capture.id), "wardrive.txt")
        aps_json = load_from_file(filepath)
        return render_template("wardrive_map.html", title="Show Wardrive", capture=capture, aps_json=aps_json)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("home")) 


##################################ACCESS POINT DETECTION##########################################
@app.route("/detect/start")
@login_required
def detect_start():
    """
    Start the detection of APs
    """
    try:
        start_scan(get_interfaces(Mode.MONITOR)[0].get_name())
        flash("Starting Access Point Scan", "success")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("detect_aps")) 

@app.route("/detect/stop")
@login_required
def detect_stop():
    """
    Stop the detection of APs
    """
    stop_scan()
    flash("Stopped Access Point Scan", "success")
    return redirect(url_for("detect_aps")) 

@app.route("/detect/get")
@login_required
def detect_get():
    """
    Get update on current devices. 
    """
    aps = get_aps()
    return jsonify(aps=aps)

@app.route("/detect")
@login_required
def detect_aps():
    """
    Display detection information on webapp
    """
    #is an interface with monitor mode available?
    if not monitor_interface_available():
        flash("You have to enable monitor mode for one of your capable interfaces before you can do that.", "danger")
        return redirect(url_for("settings"))

    running = aps.detection_is_running()
    return render_template("detect.html", title="Detect Access Points", running=running)

@app.route("/detect/aps/<string:bssid>/<string:ssid>")
@login_required
def get_stations(bssid, ssid):
    """
    Get all stations associated with a certain AP
    """
    stations = aps.get_stations_for(bssid)
    vendors = [oui.lookup(station) for station in stations]
    size = len(stations)
    return render_template("ap.html", title="Access Point", ssid=ssid, stations=stations, vendors=vendors, size=size)


###########################################SERVER RELATED###########################################

@app.route("/server/connect", methods=["GET", "POST"])
@login_required
def server_connect():
    """
    Try to connect to server with admin account
    """
    form = ServerConnectionForm()

    if not form.validate_on_submit():
        return render_template("connect_to_server.html", title="Connect to wsniff server", form=form)

    domain = form.server_domain.data
    username = form.username.data
    password = form.password.data

    server.set_domain(domain)
    if not server.server_is_available():
        flash("Server can't be reached. Please check your connection.", "danger")
        return render_template("connect_to_server.html", title="Connect to wsniff server", form=form)

    #try to autheticate
    if not server.authenticate(username, password):
        flash("Your login credentials are wrong", "danger")
        return render_template("connect_to_server.html", title="Connect to wsniff server", form=form)

    flash("You are now logged in on server as admin", "success") 
    return redirect(url_for("server_home"))

@app.route("/server", methods=["GET"])
@login_required
def server_home():
    """
    Display base site of server
    """
    if not server.has_access():
        return redirect(url_for("server_connect"))
    
    user = server.get('/users/me')
    device_registered = server.is_device_registered()
    is_admin = server.is_admin()
    return render_template("server_home.html", title="Server", user=user, device_registered=device_registered, admin=is_admin)

@app.route("/server/connect-device", methods=["GET", "POST"])
@login_required
def server_connect_device():
    """
    Try to connect this device using stored credentials
    """
    if server.connect_device():
        flash("Device is connected.", "success")
        return redirect(url_for('server_home')) 
    else:
        flash("Device could not connect.", "danger")
        return redirect(url_for('server_connect')) 

@app.route("/server/register", methods=["GET", "POST"])
@login_required
def server_register_device():
    """
    Register this device on the server and store credentials for future access
    """
    if not server.has_access():
        return redirect(url_for("server_connect"))

    form = ServerDeviceRegistrationForm()

    if form.validate_on_submit():
        device_name = form.device_name.data

        #if device could be registered successfully and reauthetication worked
        if server.register_device(device_name):
            flash("Device was registered. Your device is now fully connected.", "success")
            return redirect(url_for('server_home'))
        else:
            #it could be that there already is a device with that name
            flash("Registration failed. Maybe there is already a device with that name.", "danger")
    
    return render_template("server_register_device.html", title="Register device", form=form)


@app.route("/settings/wifi-external", methods=["GET", "POST"])
@login_required
def configure_external_wifi():
    """
    Store credentials to access other Wi-Fi networks. 
    You need a reboot to actually connect to that network with your raspberry.
    """

    form = ExternalWiFiForm()
    if form.validate_on_submit():
        ssid = form.ssid.data
        password = form.password.data
        
        #check if copy of original file does not yes exist (equivalent to configuring the first time)
        wpa_supplicant_path = "/etc/wpa_supplicant/wpa_supplicant.conf"
        backup_path = WPA_SUPPLICANT_BACKUP_PATH
        if not os.path.exists(backup_path):
            #create backup
            shutil.copyfile(wpa_supplicant_path, backup_path)
        
        #take backup file and add information to access external wifi
        shutil.copyfile(backup_path, wpa_supplicant_path) #original file
        network_info = f"""network={{\n\tssid="{ssid}"\n\tpsk="{password}"\n\tkey_mgmt=WPA-PSK\n}}\n""" #you need double curly brackets to escape them in format-strings
        with open(wpa_supplicant_path, "a") as f: #now add new information to file
            f.write(network_info)


        flash(f"New configuration was saved.", "success")
        return redirect(url_for("settings"))
    
    #displayed 
    return render_template("configure_external_wifi.html", title="Configure external wifi", form=form)