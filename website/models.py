from datetime import datetime
from enum import unique
from flask import current_app

from flask_login import UserMixin
from website import db, login_manager

#used by login_manager to login user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#also extending UserMixin from flask_login allows passing a User object to login_user
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    captures = db.relationship("Capture", backref="user", lazy=True)

    def __repr__(self):
        return f"User('{self.id}', '{self.username}')"


class Capture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    desc = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    filename = db.Column(db.String(20), nullable=False, unique=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self):
        return f"Capture('{self.id}', '{self.title}', '{self.date_posted}')"