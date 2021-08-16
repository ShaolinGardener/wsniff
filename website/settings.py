INTERFACE = "wlan1mon" #wlan1mon en0
GPS_SERIAL = "/dev/serial0" #/dev/serial0

DISPLAY_ENABLED = False

WPA_SUPPLICANT_BACKUP_PATH = "/etc/wpa_supplicant/wpa_supplicant.conf.wsniff.backup"

FLASK_THREADED = True
FLASK_DEBUG = True #TODO: change for production

SQLALCHEMY_DATABASE_URI = "sqlite:///db.sqlite"
SQLALCHEMY_TRACK_MODS = False

