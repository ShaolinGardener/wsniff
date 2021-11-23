from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

import os
from website.oui import load_local_oui
import display.display as display
import website.network as network
from website.settings import ROLE


app = Flask(__name__)
app.config["SECRET_KEY"] = "67f0cd4a6eb52e2de19ab8c908b30df9"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "You have to log in before using wsniff."
login_manager.login_message_category = "danger"

from website.models import Capture, User


#because of gunicorn you have to call this in __init__.py
def setup():
    load_local_oui(directory_path="./website/static/res")

    #create temp directory
    temp_dirpath = os.path.join(app.root_path, "static", "tmp")
    if not os.path.exists(temp_dirpath):
        os.makedirs(temp_dirpath)
        print("[+] Created temp directory")

    #is this the first time the program is started -> setup DB
    if not os.path.exists(os.path.join(app.root_path, "db.sqlite")):
        print("[+] Create empty database")
        db.drop_all()
        db.create_all()

    #in order for sqlite to pay attention to the foreign key constraint
    #(and also things like ON DELETE CASCADE) you have to call 
    #'PRAGMA foreign_keys = ON;' EVERY time you connect to your sqlite db
    db.session.execute('PRAGMA foreign_keys = ON;')
    db.session.commit()

    #if this is a slave, wait till a connection has been established
    if ROLE == "SLAVE":
        network.get_slave().find_master()

    #start display
    display.startup()
#call setup methode (needs to be done this way because of gunicorn)
setup()

from website import routes
