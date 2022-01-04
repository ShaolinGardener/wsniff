from tempfile import tempdir
from flask import render_template, url_for, flash, redirect, request, jsonify, send_from_directory
from flask_login import login_required, login_user, logout_user, current_user

from website import app, db, bcrypt
from website.forms import RegistrationForm, LoginForm, CaptureAllForm, WardrivingForm, ExternalWiFiForm, ServerConnectionForm, ServerDeviceRegistrationForm
from website.models import Device, OnlineMap, User, Capture, CaptureState, CaptureType, FullCapture, Map, Discovery, Sniffer

import website.capture.capture as capture
from website.capture.behavior import CaptureAllBehavior, MapAccessPointsBehavior, OnlineMapBehavior
import website.aps as aps
from website.aps import start_scan, stop_scan, get_aps
import website.gps as gps
from website.interfaces import Interface, get_interfaces, Mode, monitor_interface_available, get_all_interfaces
import website.oui as oui
from website.settings import WPA_SUPPLICANT_BACKUP_PATH, PORT_SLAVE
import website.server as server
import website.api as api
import website.network as network

import display.display as display

import requests
from sqlalchemy import desc
import secrets
import base64
import math
import socket
import os, shutil
import subprocess
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
    
    #get running captures
    running_captures = [c for c in current_user.captures if c.id in running_ids]
    
    #old_captures_capture_all = [c for c in current_user.captures if c.id not in running_ids and c.type == CaptureType.CAPTURE_ALL]
    #old_captures_capture_all.sort(key= lambda cap: cap.date_created, reverse=True)
    #old_captures_wardriving = [c for c in current_user.captures if c.id not in running_ids and c.type == CaptureType.WARDRIVING]
    #old_captures_wardriving.sort(key= lambda cap: cap.date_created, reverse=True)

    #get finished captures
    old_captures_capture_all = FullCapture.query.filter(Capture.user_id == current_user.id) \
                .filter(~Capture.id.in_(running_ids)) \
                .order_by(desc(Capture.date_created)).all()

    old_captures_wardriving = Map.query.filter(Capture.user_id == current_user.id) \
                .filter(~Capture.id.in_(running_ids)) \
                .order_by(desc(Capture.date_created)).all()
    db.session.commit()

    interface_available = monitor_interface_available()
    return render_template("home.html", title="Home", interface_available=interface_available, running=running_captures, old_capture_all=old_captures_capture_all, old_wardriving=old_captures_wardriving)

@app.route('/capture/delete_modal/<int:id>')
@login_required
def show_delete_modal(id: int):
    return render_template("delete_capture.html", title="Delete Capture", id=id)

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


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # standard address of gateway of most routers
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address

@app.route("/settings")
@login_required
def settings():
    """
    Display the settings of this device
    """
    managed = get_interfaces(Mode.MANAGED)
    monitor = get_interfaces(Mode.MONITOR)
    gps_running = gps.gps_is_running()
    ip = get_ip()
    return render_template("settings.html", title="Settings", managed=managed, monitor=monitor, gps_running=gps_running, ip_address=ip)

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

@app.route("/capture/new/select")
@login_required
def new_capture_selection():
    """
    Show all caputure modes available
    """
    #is an interface with monitor mode available?
    # if not monitor_interface_available():
    #     flash("You have to enable monitor mode for one of your capable interfaces before you can do that.", "danger")
    #     return redirect(url_for("settings"))

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
        title = form.title.data
        desc = form.desc.data
        user_id = current_user.id
        is_distributed = form.distributed_capture.data
        
        cap_data = {
            "capture_type": capture_type,
            "title": title,
            "desc": desc,
            "user_id": user_id,
            "is_distributed": is_distributed,
        } 

        #add capture type specific information
        #TODO: support multiple channels on frontend
        channels = None
        if capture_type == CaptureType.CAPTURE_ALL:
            channels = [form.channel.data]
            cap_data["gps_tracking"] = form.gpsTracking.data
        elif capture_type == CaptureType.WARDRIVING:
            channels = list(range(1, 14))
        elif capture_type == CaptureType.ONLINE_WARDRIVING:
            #first call this before on the master
            channels = list(range(1, 14))
            server_map_id = api.create_map(title, description=desc)
            cap_data["server_map_id"] = form.server_map_id.data
        else:
            flash("This capture type does not exist.", "success")
            return redirect(url_for("home"))
        
        #split the channels between all participants
        #for each participant, add a list of channels to channel_workloads
        #this way, you can simply pop an element of the workload and use that as the channels
        #of that local capture
        channel_workloads = []
        other_participants = network.get_master().get_connected_devices()
        n = 1 + len(other_participants)
        channel_workloads = []
        workload_size = math.ceil(len(channels)/n)
        #workload_size = len(channels) // n
        for workload_i in range(n):
            start = workload_i*workload_size
            if workload_i != n-1:
                end = start+workload_size
            else:
                end = len(channels)
            channel_workloads.append(channels[start:end])


        #create local capture (on this master sniffer)
        cap_data["channels"] = channel_workloads.pop()
        resp = requests.post(f"http://localhost:80{url_for('create_local_capture')}", json=cap_data)
        data = resp.json()
        msg = data.get("message", "Error occured.")
        
        #in case an error occurs, display the error message
        #otherwise display that the capture started successfully
        cap_id = None                                      
        if resp.status_code != 200:
            flash(msg, "danger")
            return redirect(url_for("home"))
        else:
            cap_id = data.get("cap_id")
        
        #distributed capture
        if is_distributed:
            cap: Capture = Capture.query.get(cap_id)
            #if this is a distributed capture, store the participating nodes
            other_participants = network.get_master().get_connected_devices()
            for participant in other_participants:
                cap.add_participant(participant)
                
            #generate a global id 
            #it should identify the global (distributed) capture
            #across all participating devices: use a hierarchal structure
            device_id = Device.query.first().device_identifier
            global_id = f"{device_id}:{cap_id}"
            
            #update existing local entry on master
            cap.global_id = global_id
            #save changes to the local capture
            db.session.commit()
            #our local capture entry on the master is finally complete
            
            #now we can create the local captures on the other participating nodes
            cap_data["global_id"] = global_id
            for participant in other_participants:
                cap_data["channels"] = channel_workloads.pop()
                resp = requests.post(f"http://{participant.get_ip_address()}:{PORT_SLAVE}{url_for('create_local_capture')}", json=cap_data)
                if resp.status_code != 200:
                    #TODO: here an undo of adding all previous local captures would be necessary
                    print(data)
                    print(resp.json().get("message", "Error occured"))
                else:
                    print(resp.json().get("message"))
            #all local captures should now be in state PREPARED
            
            #start the local captures on the other nodes
            for participant in other_participants:
                resp = requests.get(f"http://{participant.get_ip_address()}:{PORT_SLAVE}{url_for('start_global_capture', global_id=global_id)}")
                if resp.status_code != 200:
                    #TODO: here an undo would be necessary
                    print(resp.json().get("message", "Error occured"))
            #all local captures except the one on the master should be in state RUNNING
            #now, just like in the solitary mode, start the local capture on this master node

        #after creating the local capture on this node, we can start it (solitary as well as distributed capture mode)
        resp = requests.get(f"http://localhost:80{url_for('start_local_capture', cap_id=cap_id)}")
        data = resp.json()
        msg = data.get("message", "Error occured")

        if resp.status_code == 200:
            flash(msg, "success")
        else:
            flash(msg, "danger")

        return redirect(url_for("home"))

    gps_available = gps.is_gps_available()
    distributed_capture_possible = len(network.get_master().get_connected_devices()) > 0

    return render_template("add_capture.html", title="Add Capture", capture_type=capture_type, form=form, gps_available=gps_available, distributed_capture_possible=distributed_capture_possible)

def _get_unique_dir_path(title: str):
    """
    Returns a unique directory path so that no 2 captures will have the same path.
    """
    while True:
        postfix = secrets.token_hex(8)
        dir_name = f"{title}_{postfix}"

        #if there already is a full capture with that dir_name, try a new one, 
        #else we are finished 
        c = FullCapture.query.filter_by(dir_name=dir_name).first()
        if c:
            continue
        else:
            return dir_name

@app.route("/capture/local", methods=["POST"])
def create_local_capture():
    cdata = request.json
    capture_type = cdata.get("capture_type")
    title = cdata.get("title")
    desc = cdata.get("desc")
    user_id = cdata.get("user_id")
    channels = cdata.get("channels")
    is_distributed = cdata.get("is_distributed")
    
    if not all(v is not None for v in [capture_type, title, desc, user_id, channels, is_distributed]):
        return jsonify({'message': 'Data missing.'}), 400 

    #None in case no global_id is provided (e.g. it is not a distributed capture
    #or the global_id is yet to be computed)
    global_id = cdata.get("global_id")

    #depending on the capture type, init capture and capture_behavior 
    #with different objects 
    if capture_type == CaptureType.CAPTURE_ALL:
        gps_tracking = cdata.get("gps_tracking")
        dir_name = _get_unique_dir_path(title)

        cap = FullCapture(title=title, desc=desc, user_id=user_id, 
                            gps_tracking=gps_tracking, dir_name=dir_name, 
                            is_distributed=is_distributed, global_id=global_id)
    
    elif capture_type == CaptureType.WARDRIVING:
        #create map DB entry
        cap = Map(title=title, desc=desc, user_id=user_id, 
                    is_distributed=is_distributed, global_id=global_id)
    
    elif capture_type == CaptureType.ONLINE_WARDRIVING:
        #try to create map online
        try:
            #create new map on server
            server_map_id = cdata.get("server_map_id")
            #create local instance of map
            #TODO: here we should also pass a server_id 
            cap = OnlineMap(title=title, desc=desc, user_id=user_id, 
                            server_map_id=server_map_id, global_id=global_id,
                            is_distributed=is_distributed)
        except:
            return jsonify({'message': 'Online map creation failed.'}), 400
        
    else:
        return jsonify({'message': 'This capture type does not exist.'}), 400

    #now set the channels which this capture should observe
    cap.add_channels(channels)

    #in case this is a dristributed capture, store the global id
    if is_distributed:
        cap.global_id = global_id
    
    #add capture object to database
    #remove channel out of Capture model
    try: 
        cap.state = CaptureState.PREPARED
        db.session.add(cap)
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({'message': 'Capture creation failed.'}), 400

    #if everything went well, we can now return the capture id of this new entry
    return jsonify({'message': 'Created new capture entry.', 'cap_id': cap.id}), 200
    

@app.route("/capture/global/<string:global_id>/start", methods=["GET"])
def start_global_capture(global_id: str):
    """
    Find the local capture on this slave node that belongs to the given global capture and cause it to start 
    """
    cap = Capture.query.filter_by(global_id=global_id).first()
    if cap is None:
        return jsonify({'message': f'Capture with global id "{global_id}" does not exist.'}), 400 

    #now we can find out the local capture id of this part of the global capture
    id = cap.id

    resp = requests.get(f"http://localhost:{PORT_SLAVE}{url_for('start_local_capture', cap_id=id)}")
    #we don't care whether this was successful or not, just relay the result to the master node
    return jsonify(resp.json()), resp.status_code

@app.route("/capture/local/<int:cap_id>/start", methods=["GET"])
def start_local_capture(cap_id):
    cap = Capture.query.get(cap_id)
    if not cap:
        return jsonify({'message': f'Capture with local ID {cap_id} does not exist.'}), 400

    #create a matching capture behavior based on the information stored in the database
    if isinstance(cap, FullCapture):
        capture_behavior = CaptureAllBehavior(cap)
    elif isinstance(cap, Map):
        capture_behavior = MapAccessPointsBehavior(cap)
    elif isinstance(cap, OnlineMap):
        capture_behavior = OnlineMapBehavior(cap)
    else:
        return jsonify({'message': f'start_local_capture for captures of type {cap.type} has not been implemented.'}), 400

    #create captureBehavior and start capture with an ID that belongs 
    #to that capture in the database (since we know for sure then that 
    #there won't be two running captures with the same id )
    id = cap.id
    #there should be one since we have checked before
    interfaces = get_interfaces(Mode.MONITOR)

    #actually start capture
    try:
        capture.start_capture(id, interfaces, capture_behavior)
        cap.state = CaptureState.RUNNING
        db.session.commit()
        #SUCCESS
        return jsonify({'message': f'Capture {cap.title} started'}), 200
    except ValueError as e:
        #capture state in DB is FAILED by default when created, so we don't need to set this here
        return jsonify({'message': f'Capture {cap.title} already running'}), 400


@app.route("/capture/<int:id>/stop")
@login_required
def capture_stop(id):
    """
    Stop a certain capture
    """
    cap: Capture = Capture.query.get(id)
    if cap is None:
        flash(f"Capture with id '{id}' does not exist.", "danger")
        return redirect(url_for("home"))

    if cap.is_distributed:
        other_sniffers = cap.sniffers

        global_id = cap.global_id

        #stop local captures that belong to this (distributed) global capture
        for sniffer in other_sniffers:
            participant = network.get_master().get_device(sniffer.device_identifier)
            resp = requests.get(f"http://{participant.get_ip_address()}:{PORT_SLAVE}/{url_for('stop_global_capture', global_id=global_id)}")
            data = resp.json()
            msg = data.get("message", "Error occured")
            if resp.status_code != 200:
                #todo: some kind of recovery
                flash(f"Error stopping capture on device {sniffer.device_identifier}: {msg}", "danger")
                return redirect(url_for("home"))
        #TODO: stop local master capture

        #then collect and integrate the data on the master node
        for participant in other_sniffers:
            #just for testing:
            continue

            resp = requests.get(f"http://{participant.ip_address}:{PORT_SLAVE}/{url_for('collect_local_capture', global_id=global_id)}")
            data = resp.json()
            msg = data.get("message", "Error occured")
            if resp.status_code != 200:
                #todo: some kind of recovery
                flash(f"Error collecting data on device {participant.ip_address}: {msg}", "danger")
                return redirect(url_for("home"))
            
            #else (received data of this local capture)
            #how we need to integrate the data depends on the capture type
            if isinstance(cap, FullCapture):
                #for every observed channel we want a separate capture file
                pass
            if isinstance(cap, Map):
                #add discoveries belonging to this global capture to the local master capture
                pass

            #TODO: now we can set the global capture to FINISHED
            #since we collected all the data of this global capture on this master node, we can delete it on the other nodes
            #but we don't have to do this here synchronously but can also do it later (in theory)
         
    #if this is a normal local capture in solitary mode or a part of a global capture, either way we want to 
    #stop this local capture on the master node here
    resp = requests.get(f"http://localhost:80/{url_for('stop_local_capture', id=id)}")
    data = resp.json()
    msg = data.get("message", "Error occured")
    if resp.status_code == 200:
        flash(msg, "success")
    else:
        flash(msg, "danger")

    return redirect(url_for("home"))

@app.route("/capture/global/<string:global_id>/stop", methods=["GET"])
def stop_global_capture(global_id: str):
    """
    Find the local capture on this device that belongs to the given global capture and cause it to stop 
    """
    cap = Capture.query.filter_by(global_id=global_id).first()
    if cap is None:
        return jsonify({'message': f'Capture with global id "{global_id}" does not exist.'}), 400 

    #now we can find out the local capture id of this part of the global capture
    id = cap.id

    #stop the actual capture process and all threads attached to it
    try:
        capture.stop_capture(id)
    except ValueError as e:
        return jsonify({'message': f'Capture with id "{id}" can\'t be stopped.'}), 400

    #change the state of the capture record to completed
    cap.state = CaptureState.COMPLETED
    db.session.commit()
    return jsonify({'message': f"Capture '{cap.title}' stopped."}), 200 


@app.route("/capture/local/<int:id>/stop", methods=["GET"])
def stop_local_capture(id: int):
    """
    Actually carries out stopping a LOCAL capture with the given id 
    """
    cap = Capture.query.get(id)
    if cap is None:
        return jsonify({'message': f'Capture with id "{id}" does not exist.'}), 400

    #stop the actual capture process and all threads attached to it
    try:
        capture.stop_capture(id)
    except ValueError as e:
        return jsonify({'message': f'Capture with id "{id}" can\'t be stopped.'}), 400

    #change the state of the capture record to completed
    cap.state = CaptureState.COMPLETED
    db.session.commit()
    return jsonify({'message': f"Capture '{cap.title}' stopped."}), 200


@app.route("/capture/<string:global_id>/global/collect", methods=["GET"])
@login_required
def collect_global_capture(global_id: str):
    """
    Collect all the local captures of this distributed global capture and integrate the data on the master node.
    """
    cap = Capture.query.filter_by(global_id=global_id).first()
    if cap is None:
        return jsonify({'message': f'Capture with global id "{global_id}" does not exist.'}), 400 

    other_sniffers = cap.sniffers
    for sniffer in other_sniffers:
        participant = network.get_master().get_device(sniffer.device_identifier)
        resp = requests.get(f"http://{participant.get_ip_address()}:{PORT_SLAVE}/{url_for('collect_local_capture', global_id=global_id)}")
        data = resp.json()
        msg = data.get("message", "Error occured")
        if resp.status_code != 200:
            #todo: some kind of recovery
            flash(f"Error collecting data on device {participant.get_device_id()}: {msg}", "danger")
            return redirect(url_for("home"))
        else:
            print(f"[+] <{participant.get_device_id()}>: {msg}")
 
        #else (received data of this local capture)
        #how we need to integrate the data depends on the capture type
        if isinstance(cap, FullCapture):
            #get filename and the encoded content of the .pcap file 
            filename = data.get("captured_data").get("filename")
            file_path = os.path.join(cap.get_dir_path(), filename)

            encoded_content = data.get("captured_data").get("encoded_content")
            captured_data = base64.b64decode(encoded_content)

            try:
                file = open(file_path, "wb")
                file.write(captured_data)
                print(f"[+] Wrote data of {participant.get_device_id()}")
            except Exception as e:
                print(f"[-] Error writing data: {e}")
        elif isinstance(cap, Map):
            #add discoveries belonging to this global capture to the local master capture
            discoveries = data.get("captured_data", [])
            for discovery in discoveries:
                d = Discovery.create_from_dict(discovery)
                d.map_id = cap.id
                try:
                    db.session.add(d)
                    db.session.commit()
                except Exception as e:
                    print(f"[-] Error adding discovery from {participant.get_device_id()}: {e}")
        else:
            #this case is already handled in collect_local_capture (and is caught above when handling the HTTP response)
            pass

        #completely unrelated to the type of capture are the channels this local capture observed
        #also integrate this information
        channels = data.get("channels")
        if channels is None:
            flash("Participant was missing channel information.", "danger")
        cap.add_channels(channels)

        #delete the data on the node we just retrieved it from
        resp = requests.get(f"http://{participant.get_ip_address()}:{PORT_SLAVE}/{url_for('delete_local_capture', id=global_id, id_type='global_id')}")
        data = resp.json()
        msg = data.get("message", "Error occured")
        if resp.status_code != 200:
            #undo all previous deletions to remain in a consistent state
            db.session.rollback()
            flash(f"Error deleting data on device <{participant.get_device_id()}>: {msg}", "danger")
            return redirect(url_for("home"))
        else:
            #actually update channel list
            db.session.commit()
            print(f"[+] <{participant.get_device_id()}>: {msg}") 
    
    
    #now that all information is stored on this node, this has become a real local capture
    for sniffer in cap.sniffers:
        db.session.delete(sniffer)
    cap.global_id = None
    cap.is_distributed = False
    db.session.commit()

    flash("Collected and integrated the entire data on this device.", "success")
    return redirect(url_for("home"))

@app.route("/capture/local/<string:global_id>/collect", methods=["GET"])
def collect_local_capture(global_id: str):
    """
    Find the local capture on this device that belongs to the given global capture and collect its data 
    """
    cap = Capture.query.filter_by(global_id=global_id).first()
    if cap is None:
        return jsonify({'message': f'Capture with global id "{global_id}" does not exist.'}), 400 

    #now we can find out the local capture id of this part of the global capture
    id = cap.id

    #retrieve the channels that were observed
    channels = cap.get_channels()

    #collect the local data of this global capture
    #for this purpose, store the captured data in a generic variable whose
    #content depends on the capture type
    captured_data = None
    if isinstance(cap, FullCapture):
        pcap_filepath = os.path.join(cap.get_dir_path(), "cap.pcap")
        #to make sure the file has a unique name on the master node, just use the device id of this sniffer
        new_filename = Device.query.first().device_identifier + ".pcap"
        with open(pcap_filepath, "rb") as file:
            file_content = file.read()
            #create base 64 string representation of the file 
            encoded_content = base64.b64encode(file_content).decode("utf-8")
            captured_data = {
                "filename": new_filename,
                "encoded_content": encoded_content
            }
    elif isinstance(cap, Map):
        captured_data = []
        for discovery in cap.discoveries:
            d = discovery.get_as_dict()
            captured_data.append(d)
    else:
        return jsonify({'message': f"Data collection for this capture type is not implemented."}), 400  

    #return the local capture data as JSON
    return jsonify({
        'message': f"Data collected successfully.",
        'channels': channels, 
        'captured_data': captured_data
    }), 200 


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
    if not c:
        flash(f"Capture with id '{id}' does not exist.", "success")
        return redirect(url_for("home"))

    #if it is a full capture
    if isinstance(c, FullCapture):    
        dir_path = c.get_dir_path()
        
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

    elif isinstance(c, Map):
        #TODO: this also includes OnlineMaps (but only the local discoveries)
        discoveries = c.discoveries
        out_dirpath = os.path.join(app.root_path, "static", "tmp")
        out_filepath = os.path.join(app.root_path, "static", "tmp", c.title)
        file = open(out_filepath, "w")
        file.write("{discoveries: [\n")
        for d in discoveries:
            out = json.dumps(d.get_as_dict())
            file.write(f"{out},\n")
        file.write("]}")
        file.close()
        return send_from_directory(directory=out_dirpath, filename=c.title, as_attachment=True, attachment_filename=c.title.replace(" ", "_"))

    return redirect(url_for("home"))

@app.route("/capture/<int:id>/delete")
@login_required
def capture_delete(id: int):
    cap = Capture.query.get(id)
    if cap is None:
        flash(f'Capture with id "{id}" does not exist.')
    
    if cap.is_distributed:
        #delete data on other nodes
        other_sniffers = cap.sniffers
        global_id = cap.global_id
        for sniffer in other_sniffers:
            participant = network.get_master().get_device(sniffer.device_identifier)
            resp = requests.get(f"http://{participant.get_ip_address()}:{PORT_SLAVE}/{url_for('delete_local_capture', id=global_id, id_type='global_id')}")
            data = resp.json()
            msg = data.get("message", "Error occured")
            if resp.status_code != 200:
                #undo all previous deletions to remain in a consistent state
                db.session.rollback()
                flash(f"Error deleting data on device <{participant.get_device_id()}>: {msg}", "danger")
                return redirect(url_for("home"))
            else:
                print(f"[+] <{participant.get_device_id}>: {msg}")

    #delete local capture on this node
    resp = requests.get(f"http://localhost:80/{url_for('delete_local_capture', id=id, id_type='local_id')}")
    data = resp.json()
    msg = data.get("message", "Error occured")
    if resp.status_code == 200:
        flash(msg, "success")
    else:
        db.session.rollback()
        flash(msg, "danger")
    
    #only commit here so that the changes only apply if all deletions were possible
    try:
        db.session.commit()
    except Exception as e:
        print(e)
        return jsonify({"message": f"Error when trying to delete capture from database."}), 400

    return redirect(url_for("home"))


@app.route("/capture/local/<id>/delete")
def delete_local_capture(id):
    """
    Delete a local capture including its DB entries and files.

    :param id: ID which uniquely identifies this local capture. Can be a local ID, but also a global ID.
    :param id_type: Should be passed as a query parameter .Indicates whether the id is a local or global ID. 
                 Should be either set to 'local_id' or 'global_id'
    """
    #get id type
    id_type = request.args.get('id_type')
    if id_type is None:
        return jsonify({"message": f"You need to specify an id type as a HTTP query parameter."}), 400
    
    #retrieve the capture depending on the id type
    c = None
    if id_type == "local_id":
        c = Capture.query.get(id)
    elif id_type == "global_id":
        c = Capture.query.filter_by(global_id=id).first()
    else:
        return jsonify({"message": f"This ID type is not supported."}), 400 
    
    if not c:
        return jsonify({"message": f"Capture with ID '{id}' does not exist."}), 400
    
    #set a default capture type name for the message sent back to the user
    capture_type = "Capture"

    #do cleanup depending on type of capture
    if isinstance(c, FullCapture):
        #delete saved files
        path = c.get_dir_path()
        try:
            if os.path.exists(path):
                shutil.rmtree(path)
        except OSError as e:
            flash(f"Could not delete directory {path}")
    elif isinstance(c, Map):
        capture_type = "Map"

    #delete it from the database
    try:
        db.session.delete(c)
        #TODO: don't commit here (we want to do that at a higher level to keep consistency)
        db.session.commit()
        return jsonify({"message": f"{capture_type} '{c.title}' was successfully deleted."}), 200
    except Exception as e:
        print(e)
        return jsonify({"message": f"Error when trying to delete capture from database."}), 400


@app.route('/wardrive/<id>/aps', methods=['GET'])
@login_required
def get_map_discoveries(id):
    """
    Returns all discoveries that belong to this map that are within the rectangle defined by 
    [lat1, lon1] and [lat2, lon2]
    """
    map = Map.query.filter_by(id=id).first_or_404()

    #get query parameters
    lat1, lat2 = request.args.get('lat1'), request.args.get('lat2')
    lon1, lon2 = request.args.get('lon1'), request.args.get('lon2')

    if not (lat1 and lat2 and lon1 and lon2):
        return jsonify({'message': 'Please provide lat and lon values'}), 400
    else:
        #parse arguments (query params are strings)
        lat1, lat2 = float(lat1), float(lat2)
        lon1, lon2 = float(lon1), float(lon2)

    lat_min, lon_min = min(lat1, lat2), min(lon1, lon2)
    lat_max, lon_max = max(lat1, lat2), max(lon1, lon2)

    discoveries = Discovery.query.filter_by(map_id=map.id).filter( 
        Discovery.gps_lat >= lat_min, Discovery.gps_lat <= lat_max, 
        Discovery.gps_lon >= lon_min, Discovery.gps_lon <= lon_max).all()

    #construct JSON output and return it
    output = []
    for discovery in discoveries:
        output.append(discovery.get_as_dict())
    return jsonify({'discoveries': output})

@app.route("/wardrive/<int:id>")
@login_required
def wardrive_capture_show(id):
    """
    Show an local wardriving map
    """
    try:
        map = Map.query.get(id)
        if not map:
            raise Exception("Map does not exist")
        return render_template("local_map.html", title="Show local map", map=map)
    except Exception as e:
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
        start_scan(get_interfaces(Mode.MONITOR))
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
    
    online_maps = api.get_all_maps()
    local_maps = OnlineMap.query.all()
    return render_template("server_home.html", title="Server", user=user, device_registered=device_registered, admin=is_admin, online_maps=online_maps, local_maps=local_maps)

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

@app.route("/server/maps/<id>/show", methods=["GET"])
@login_required
def server_map_show(id):
    """
    Show an online wardriving map
    """
    try:
        map = api.get_map(id)
        api_token = server.get_auth_token() 
        return render_template("online_map.html", title="Show online map", map=map, api_token=api_token)
    except Exception as e:
        flash(str(e), "danger")
        return redirect(url_for("home"))


def server_map_capture(id):
    """
    Capture packets and add it to the existing map with ID <id>
    Might raise an Exception in case anything goes wrong starting the capture.
    """
    map = Map.query.filter_by(id=id).first()
    if not map:
        raise Exception("Map does not exist")

    #create captureBehavior and start capture
    id = map.id
    capture_behavior = OnlineMapBehavior(map)
    
    #actually start capture
    try:
        capture.start_capture(id, get_interfaces(Mode.MONITOR)[0], capture_behavior)
        map.state = CaptureState.RUNNING
        db.session.commit()
        flash(f"Capture started", "success")
    except ValueError as e:
        #capture state in DB is FAILED by default when created, so we don't need to set this here
        flash(f"Capture already running.", "danger")
    
    return #attention: returns to a route function

@app.route("/server/maps/<id>/participate", methods=["GET"])
@login_required
def server_map_participate(id):
    """
    Contribute to a map which already exists.
    """
    if not monitor_interface_available():
        flash("You have to enable monitor mode for one of your capable interfaces before you can do that.", "danger")
        return redirect(url_for("settings"))
    if not gps.is_gps_available():
        flash("You have to enable GPS before you can do that.", "danger")
        return redirect(url_for("settings"))

    #map already exists on server, so we just have to create a local instance
    #with fitting infos: retrieve infos of online map and create local instance based on that
    o_map = None
    try: 
        o_map = api.get_map(id)
    except api.ApiException as e:
        flash(str(e), "danger")
        return redirect(url_for('server_home'))

    #most important step here when creating a local instance is to store the correct server_map_id
    #TODO: pass server_id
    map = OnlineMap(title=o_map["title"], desc=o_map["desc"], user_id=current_user.id,
                    server_map_id=o_map["id"])
    try: 
        db.session.add(map)
        db.session.commit()
    except Exception as e:
        print(e)
        flash("Local map creation failed.", "danger")
        return redirect(url_for('server_home')) 
    
    try:
        #start capture in separate thread
        server_map_capture(id)
    except:
        return redirect(url_for('server_home')) 
    
    return redirect(url_for('home'))


@app.route("/maps/<int:id>/delete", methods=["GET"])
@login_required
def server_map_local_delete(id: int):
    map = OnlineMap.query.filter_by(id=id).first_or_404()
    try:
        db.session.delete(map)
        db.session.commit()
        flash("Local data was deleted.", "success")
    except Exception as e:
        flash("Could not delete local map data.", "danger")
    return redirect(url_for("server_home"))

@app.route("/server/maps/<int:id>/delete", methods=["GET"])
@login_required
def server_map_delete(id):
    if api.delete_map(id):
        flash("Map was deleted", "success")
    else:
        flash("Map could not be deleted", "danger")
    return redirect(url_for("server_home"))

@app.route('/oui/<mac>', methods=["GET"])
#TODO: authetication
def lookup_oui(mac:str):
    """
    Returns the vendor information for this mac address
    """
    return jsonify({'vendor': oui.lookup(mac)})

@app.route('/devices/<ip>/oui/<mac>', methods=["GET"])
@login_required
def remote_lookup_oui(ip:str, mac:str):
    """
    Returns the vendor information for this mac address
    """
    resp = requests.get(f"http://{ip}:4242/oui/{mac}")
    print(resp.text)
    if resp.status_code == 200:
        return jsonify({'reply': resp.json()})

########################################wsniff devices###########################################
@app.route("/devices/connected")
@login_required
def get_connected_devices():
    """
    Look for other wsniff devices that are trying to connect.
    """
    connected = list(map(lambda participant: participant.get_dict(), network.get_master().get_connected_devices()))
    return jsonify({'connected_devices': connected})

@app.route("/devices/search")
@login_required
def start_network_discovery():
    """
    Start network discovery thread.
    """
    try:
        network.get_master().start_discovery()
        flash("Started network discovery.", "success")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for('show_network_discovery'))

@app.route("/devices/end_search")
@login_required
def stop_network_discovery():
    """
    Stop network discovery thread.
    """
    try:
        network.get_master().end_discovery()
        flash("Stopped network discovery.", "success")
    except Exception as e:
        flash(str(e), "danger")
    return redirect(url_for('show_network_discovery'))

@app.route("/devices")
@login_required
def show_network_discovery():
    """
    Display all connected devices and allow user to start and stop a pairing process.
    """
    is_running = network.get_master().is_discovery_running()
    return render_template("network_discovery.html", title="Connect", is_running=is_running) 


#################################################################################################

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

        try:
            #try to use wpa_cli to dynamically reconnect with new credentials
            cmd = "wpa_cli reconfigure"
            proc_res = subprocess.run(cmd, text=True, capture_output=True, shell=True, check=True)
            res = proc_res.stdout
            if res:
                print(f"[+] wpa_cli reconfigure: {res}")
                flash("Reconnecting to new network.", "success")
        except subprocess.CalledProcessError as e:
            #otherwise tell the user to reconnect via a reboot
            print(f"[-] wpa_cli reconfigure failed: {e}")
            flash(f"Reboot to connect to new network.", "info")


        return redirect(url_for("settings"))
    
    #displayed 
    return render_template("configure_external_wifi.html", title="Configure external wifi", form=form)