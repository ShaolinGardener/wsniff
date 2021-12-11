""" SET TO SLAVE IF THIS DEVICE SHOULD BE PART OF A CLUSTER """
ROLE="MASTER"
""" PORT ON WHICH SLAVES ARE AVAILABLE """
PORT_SLAVE = 4242

""" CONFIGURE ACCESS TO YOUR GPS MODULE HERE"""
#NEO 8M: /dev/serial0, SkyTraq Venus 8: /dev/ttyUSB0
GPS_SERIAL = "/dev/serial0"

#the baud rate is the symbol rate, i.e. the number of transferred symbols per second
#you will find it in the information sheet of your gps module, the unit will be 'Bd'
GPS_BAUD_RATE = 4800 #e.g. NEO 8M: 9600, SkyTraq Venus 8: 4800

"""
Set to 'True' if you have connected a 2.13 inch e-Paper HAT of waveshare
Set to 'False' otherwise
"""
DISPLAY_ENABLED = False

""" 
Can be helpful when you setup the software or want to develop yourself
otherwise, just change it to 'False' since wsniff will run faster.
"""
FLASK_DEBUG = True #TODO: change for production

"""
Most of the time you won't have to touch the stuff below
"""
WPA_SUPPLICANT_BACKUP_PATH = "/etc/wpa_supplicant/wpa_supplicant.conf.wsniff.backup"

FLASK_THREADED = True

SQLALCHEMY_DATABASE_URI = "sqlite:///db.sqlite"
SQLALCHEMY_TRACK_MODS = False

