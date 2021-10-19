from datetime import datetime
from enum import unique
from flask import current_app

from flask_login import UserMixin
from website import db, login_manager


#USER RELATED

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

class CaptureState:
    FAILED = 1
    RUNNING = 2
    COMPLETED = 3

class CaptureType:
    TEST = 0
    CAPTURE_ALL = 1
    WARDRIVING = 2
    ONLINE_WARDRIVING = 3

#TODO: refactor system - data like title/desc/... is stored redundantly 
#an idea would be to see the whole system as a hierachie with Capture as the base class
#-> choose another mapping option with multiple tables
class Capture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    desc = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    filename = db.Column(db.String(20), nullable=True, unique=True)
    channel = db.Column(db.Integer, nullable=True)
    gps = db.Column(db.Boolean, nullable=False, default=True)

    type = db.Column(db.Integer, nullable=False)
    state = db.Column(db.Integer, nullable=False, default=CaptureState.FAILED)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self):
        return f"Capture('{self.id}', '{self.title}', '{self.date_created}')"


class Server(db.Model):
    __tablename__ = 'server'

    id = db.Column(db.Integer, primary_key=True)
    #used to connect (a domain has a max length of 255 characters)
    domain = db.Column(db.String(255), unique=True)
    #the username this device uses on the server
    device_name = db.Column(db.String(50))
    #used to autheticate 
    pass_token = db.Column(db.String(88))

    maps = db.relationship('Map', back_populates='server')



class Map(db.Model):
    #you could also implement a inheritance hierarchie where
    #the entity types OnlineMap and LocalMap inherit from Map,
    #but due to small differences we have decided for a 1-table-solution
    #and using a dicriminator attribute (is_online)
    __tablename__ = 'map'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    desc = db.Column(db.Text, nullable=True)

    #all discoveries that were made creating this map
    discoveries = db.relationship('Discovery', back_populates='map')

    #The following attributes are only needed for OnlineMaps
    #indicates whether this is a LocalMap or an OnlineMap
    is_online = db.Column(db.Boolean, nullable=False, default=False)
    #in order to add new discoveries to the right map ON THE SERVER, we have to store
    #correspondig map id of the map on the server
    server_map_id = db.Column(db.Integer, nullable=False)

    #OnlineMaps have a server attribute (but can also be NULL for LocalMaps)
    server_id = db.Column(db.Integer, db.ForeignKey('server.id', ondelete='CASCADE'), nullable=True)
    server = db.relationship('Server', back_populates='maps')

    def __repr__(self):
        return f"Map('{self.id}', '{self.title}')"


class Encryption():
    OPEN = 0
    WEP = 1
    WPA = 2
    WPA2 = 3

#a single discovery of an access point
class Discovery(db.Model):
    __tablename__ = 'discovery'

    #ideal would be a composite primary key with mac and id since it is possible that the
    #sniffer encounters the same access point multiple times, but SQLite does not allow
    #autoincrement for composite keys/id => so just use id
    id = db.Column(db.Integer, primary_key=True)

    #for better query performance, we don't want to store it as a string but rather
    #interpret it as an integer:
    #e.g. 00-80-41-ae-fd-7e -> 0x008041AEFD7E and convert this hex number to decimal
    mac = db.Column(db.Integer, nullable=False)
    
    #don't place any constraints on the channel since the numbers can differ from country to country
    channel = db.Column(db.Integer, nullable=False)
    encryption = db.Column(db.Integer, nullable=False)
    #this is the maximum RSSI the sniffer got during the timespan he saw the AP
    signal_strength = db.Column(db.Integer, nullable=False)

    #NULL allowed for hidden APs
    ssid = db.Column(db.String(64))

    #whether this discovery has been uploaded to server
    is_uploaded = db.Column(db.Boolean(), nullable=False, default=False)
    
    #TODO
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    #gps data: latitude and longitude when the sniffer had the highest signal strength
    #(and was therefore closest to the AP)
    gps_lat = db.Column(db.Float, nullable=False)
    gps_lon = db.Column(db.Float, nullable=False)

    #the map of which this discovery is a part 
    map_id = db.Column(db.Integer, db.ForeignKey('map.id'), nullable=False)
    map = db.relationship('Map', back_populates='discoveries')