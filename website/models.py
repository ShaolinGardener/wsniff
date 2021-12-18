from datetime import datetime
from enum import unique
from flask import current_app

from flask_login import UserMixin
from website import db, login_manager, app
import os

#USER RELATED

#used by login_manager to login user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#also extending UserMixin from flask_login allows passing a User object to login_user
class User(db.Model, UserMixin):
    """
    Table which stores all the registered users.
    Used for the login process as well as displaying only the data belonging to that user.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    captures = db.relationship("Capture", backref="user", lazy=True, cascade="all, delete")

    def __repr__(self):
        return f"User('{self.id}', '{self.username}')"


class Server(db.Model):
    """
    Stores information which are used to connect to a wsniff server.
    """
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    #used to connect (a domain has a max length of 255 characters)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    #the username this device uses on the server
    device_name = db.Column(db.String(50), nullable=False)
    #used to autheticate 
    pass_token = db.Column(db.String(88), nullable=False)

    maps = db.relationship('OnlineMap', back_populates='server', cascade="all, delete")


class CaptureState:
    FAILED = 1
    RUNNING = 2
    COMPLETED = 3

class CaptureType:
    TEST = 0
    CAPTURE_ALL = 1
    WARDRIVING = 2
    ONLINE_WARDRIVING = 3

class Capture(db.Model):
    """
    Base class for all activities that involve capturing and processing 802.11 data.
    """
    __tablename__ = 'captures'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    desc = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    #CaptureStates
    state = db.Column(db.Integer, nullable=False, default=CaptureState.FAILED)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete='CASCADE'), nullable=False)

    #discrimatnor column which is used for indicating the type of object represented within this row
    type = db.Column(db.String(50))
    __mapper_args__ = {
        'polymorphic_identity': 'captures',
        'polymorphic_on': type
    }


    #channels that are observed as part of this capture
    channels = db.relationship('CaptureChannel', cascade="all, delete")


    def set_channels(self, channels: list):
        """
        Expects a list of integers representing the channel which are observed as part of this capture
        """
        for channel in channels:
            self.channels.append(CaptureChannel(capture_id=self.id, channel=channel))

    def get_channels(self):
        """
        Returns a list of integers representing the channels which this (local) capture observes
        """
        #get channel values
        channels = [ch.channel for ch in self.channels]
        return channels

    def get_channel_string(self):
        """
        Returns the channels of this capture as a shortened string representation.
        Takes an array of channels and returns a short string representation of them.
        E.g.: [1, 2, 3, 7, 11, 12] will become "1-3 7 11-12"
        """
        channels = self.get_channels()
        channels.sort()
        
        #for instance, [1, 2, 3, 4, 7, 11, 12] will be 
        #mapped to     [(1, 4), (7, 7), (11, 12)]
        res = []
        start, channel = None, None
        for channel in channels:
            if not start:
                start = channel
                predecessor = channel
                continue

            if channel == predecessor + 1:
                pass
            else:
                #end of current partition
                res.append((start, predecessor))
                #current channel is start of new partition
                start = channel

            predecessor = channel

        #add last partition
        res.append((start, predecessor))

        #now create a corresponding string
        output = ""
        for partition in res:
            if partition[0] == partition[1]:
                output += str(partition[0])
            else:
                output += f"{partition[0]}-{partition[1]}"
            output += " "
        
        #note: we could directly include the string building above 
        #(no need to create a result array) to increase performance,
        #but this way it is easier to read
        return output


    def __repr__(self):
        return f"Capture('{self.id}', '{self.title}', '{self.date_created}')"


class FullCapture(Capture):
    """
    Capture the entire traffic on the specified channels and save it to a .pcap file.
    """
    __tablename__ = 'full_captures'

    id = db.Column(db.Integer, db.ForeignKey('captures.id', ondelete='CASCADE'), primary_key=True)
    #since FullCapture is a subclass of Capture, we need to provide a value for the discrimnator attribute in Capture
    __mapper_args__ = {
        'polymorphic_identity': 'full_capture'
    }

    #the name of the directory that contains all files that belong to that full capture
    #for instance, the .pcap files 
    dir_name = db.Column(db.String(120), nullable=False)

    #whether gps information is recorded
    gps_tracking = db.Column(db.Boolean, nullable=False, default=False)
    #TODO: allow multiple channels
    channel = db.Column(db.Integer, nullable=False)

    def get_dir_path(self):
        return os.path.join(app.root_path, "static", "captures", self.dir_name)


class Map(Capture):
    """
    A wardriving capture that creates a map.
    This class entails both local maps and base informations of online maps.
    """
    #you could also implement a inheritance hierarchie where
    #the entity types OnlineMap and LocalMap inherit from Map,
    #but due to small differences we have decided for a 1-table-solution
    #and using a dicriminator attribute (is_online)
    __tablename__ = 'maps'

    id = db.Column(db.Integer, db.ForeignKey('captures.id', ondelete='CASCADE'), primary_key=True)
    
    #since Map is a subclass of Capture, we need to provide a value for the discrimnator attribute in Capture
    __mapper_args__ = {
        'polymorphic_identity': 'local_map'
    }
    
    #all discoveries that were made creating this map
    discoveries = db.relationship('Discovery', back_populates='map', cascade="all, delete")

    def __repr__(self):
        return f"Map('{self.id}', '{self.title}')"

class OnlineMap(Map):
    """
    A subclass of Map. 
    Single table inheritance that SQLAlchemy supports would be preferrable here, but
    it is not possible since we would need a second type/discriminator attribute in the map table which is not supported.
    SQLAlchemy doc: 'Currently, only one discriminator column may be set, typically on the base-most class in the hierarchy. '
    """
    __tablename__ = 'online_maps'

    #since OnlineMap is a subclass of Map, we need to provide a value for the discrimnator attribute in Capture
    __mapper_args__ = {
        'polymorphic_identity': 'online_map'
    }

    id = db.Column(db.Integer, db.ForeignKey('maps.id', ondelete='CASCADE'), primary_key=True)

    #in order to add new discoveries to the right map ON THE SERVER, we have to store
    #correspondig map id of the map on the server
    server_map_id = db.Column(db.Integer, nullable=True)

    #OnlineMaps have a server attribute (but can also be NULL for LocalMaps)
    #TODO: server_id should have a NOT NULL constraint
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id', ondelete='CASCADE'), nullable=True)
    server = db.relationship('Server', back_populates='maps')


#a single discovery of an access point
class Discovery(db.Model):
    """
    A single observation of an access point. Belongs to a certain map.
    """
    __tablename__ = 'discoveries'

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
    encryption = db.Column(db.String(20), nullable=True)
    #this is the maximum RSSI the sniffer got during the timespan he saw the AP
    signal_strength = db.Column(db.Integer, nullable=False)

    #NULL allowed for hidden APs
    ssid = db.Column(db.String(64))

    #whether this discovery has been uploaded to server
    is_uploaded = db.Column(db.Boolean(), nullable=False, default=False)
    
    timestamp = db.Column(db.DateTime, nullable=False)
    #gps data: latitude and longitude when the sniffer had the highest signal strength
    #(and was therefore closest to the AP)
    gps_lat = db.Column(db.Float, nullable=False)
    gps_lon = db.Column(db.Float, nullable=False)

    #the map of which this discovery is a part 
    map_id = db.Column(db.Integer, db.ForeignKey('maps.id', ondelete='CASCADE'), nullable=False)
    map = db.relationship('Map', back_populates='discoveries')

    def get_as_dict(self):
        """
        Returns this object as a dict since we need that for converting it to JSON
        """
        data = {
            "id": self.id,
            "mac": self.mac,
            "channel": self.channel,
            "encryption": self.encryption,
            "signal_strength": self.signal_strength,
            "ssid": self.ssid,
            "timestamp": datetime.timestamp(self.timestamp),
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon 
        }
        return data