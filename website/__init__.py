from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

import os
from website.oui import load_local_oui
import display.display as display


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

#because of gunicorn you have to call this in __init__.py
def setup():
    load_local_oui(directory_path="./website/static/res")

    #create temp directory
    temp_dirpath = os.path.join(app.root_path, "static", "tmp")
    if not os.path.exists(temp_dirpath):
        os.makedirs(temp_dirpath)
        print("[+] Created temp directory")

    #start display
    display.startup()
#call setup methode (needs to be done this way because of gunicorn)
setup()

from website import routes