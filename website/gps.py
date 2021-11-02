import sys
import io, json, re
import serial
from datetime import datetime

import pynmea2

from time import sleep, mktime, time
from website.settings import GPS_SERIAL, GPS_BAUD_RATE

from threading import Thread, Event, Lock

#enable basic testing on other OS than linux
if sys.platform.startswith('linux'):
    if GPS_SERIAL == "/dev/null":
        sio = None
    else:
        try:
            #you can change these values in settings.py
            ser = serial.Serial(GPS_SERIAL, GPS_BAUD_RATE, timeout=5.0)
        except serial.serialutil.SerialException as e:
            #if the serial port that is specified (GPS_SERIAL) cannot be opened
            print('[-] Please specify the real serial port of your GPS module ')
            print('in the settings (GPS_SERIAL). If you do not want to use a GPS module,')
            print('just set it to /dev/null')
            sys.exit(1)

        #nmea protokoll def. <CR><LF> als ende zeile -> TextIOWrapper wandelt das automatisch in \n um
        #latin 1 because it seems to have problems with utf-8
        sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser), encoding="latin1")
else:
    #you will only be able to test GPS on linux
    sio = None

print("[+] Initializing gps module")


class GPSRoute():
    def __init__(self, name: str, filepath: str, t_sample_delay=2):
        """
        t_sample_delay: every t_sample_delay seconds, a new waypoint is added when starting to track
        """
        self.name = name
        self.filepath = filepath
        self.t_sample_delay = t_sample_delay
        self.waypoints = [] #each waypoints is a tupel (timestamp, latitude, longitude)

        self._stop = Event()

    def _add_waypoint(self, latitude: float, longitude: float):
        """
        Add a single point to the gps route
        """
        new = (time(), latitude, longitude)
        self.waypoints.append(new)

    def _capture(self):
        while True:
            if self._stop.is_set():
                break
            if is_gps_available():
                lat, lon = get_gps_data()
                _add_waypoint(lat, lon)
            sleep(self.t_sample_delay)

    def start_capture(self):
        """
        Start thread for capturing a route of gps data
        """
        self.t = Thread(target=self._capture, name="gps route tracker")
        self.t.setDaemon(True)
        self.t.start()
        print(f"[+] GPS Capture '{self.name}'' Started")

    def stop_capture(self):
        self._stop.set()
        self.t.join()

        #store in file
        self.store_as_file()
        print(f"[+] GPS Capture '{self.name}'' Stopped")

    #TODO: write to file during capture (e.g. when calling _add_waypoint)
    def store_as_file(self):
        f = open(self.filepath, "w")
        for waypoint in self.waypoints:
            f.write(f"{waypoint[0]};{waypoint[1]};{waypoint[2]}\n")
        f.close()

    def load_from_file(self):
        """
        Load GPS route from file
        """
        f = open(self.filepath, "r")
        self.waypoints = []

        line = f.readline()
        while line:
            t = line.strip().split(";")
            waypoint = (float(t[0]), float(t[1]), float(t[2]))
            self.waypoints.append(waypoint)
            line = f.readline()
        f.close()

    def get_gpx(self):
        """
        Returns the data of the gps route in the GPX format
        """
        header = f"""<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
                    <gpx xmlns="http://www.topografix.com/GPX/1/1" version="1.1" creator="wsniff"
                    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xsi:schemaLocation="http://www.topografix.com/GPX/1/1 http://www.topografix.com/GPX/1/1/gpx.xsd">
                    <metadata>
                        <name>{self.name}</name>
                        <desc>a gps route made with wsniff</desc>
                        <author>
                        <name>wsniff</name>
                        </author>
                    </metadata>
                    <trk>
                        <name>{self.name}</name>
                        <trkseg>"""
        end = """       </trkseg>
                    </trk>
                </gpx>"""

        res = header
        for waypoint in self.waypoints:
            t = datetime.fromtimestamp(waypoint[0]).strftime("%Y-%m-%dT%H:%M:%S")
            res += f"""
                <trkpt lat="{waypoint[1]}" lon="{waypoint[2]}">
                    <time>{t}</time>
                </trkpt>"""
        res += end
        return res

#END OF CLASS GPSRoute



_stop_event = Event()
_stop_event.set()
_lock = Lock()
_current_position = (0.0, 0.0)
_gps_available = False


def gps_is_running():
    return not _stop_event.is_set()

def is_gps_available():
    global _gps_available
    return _gps_available

def get_gps_data():
    _lock.acquire()
    lat, lon = _current_position[0], _current_position[1]
    _lock.release()
    return lat, lon


class ChecksumException(Exception):
    """
    returns if this is a valid gga message or if it has been currupted
    raises ChecksumException in case the message has been corrupted
    """
    pass

def check_gga_checksum(line: str, given_checksum: str):
    """
    Checks whether given NMEA message is valid or if it has been corrupted somehow
    """
    #checksum is defined as XOR of all characters in the message after '$' to the beginning of the checksum (*) and is represented as a hex number
    #see protocol: http://navspark.mybigcommerce.com/content/NMEA_Format_v0.1.pdf
    relevant_for_checksum = line[1:line.rfind("*")]
    bytes = list(map(ord, relevant_for_checksum)) #bytes of line
    computed_checksum = bytes[0]
    for i in range(1, len(bytes)):
        computed_checksum = computed_checksum ^ bytes[i]

    #check if checksums match
    if int(given_checksum, 16) == computed_checksum:
        return True
    raise ChecksumException("[-] Checksum of GGA message was incorrect")


def convert(coordinate):
    """
    returns gps data in float format (which can be pasted in google for example and is needed for leaflet maps)
    found this code on github:
    Link:       https://github.com/Knio/pynmea2/blob/2dab8f59045365463a33013cd1f95140943193fd/pynmea2/nmea_utils.py#L33
    Licence:    https://github.com/Knio/pynmea2/blob/2dab8f59045365463a33013cd1f95140943193fd/LICENSE
    """
    if not coordinate or coordinate == "0":
        return 0.0
    d, m = re.match(r'^(\d+)(\d\d\.\d+)$', coordinate).groups()
    return float(d) + float(m) / 60

def _read_data():
    """
    Here the actual tracking takes place
    """
    global _current_position
    global _gps_available

    while not _stop_event.is_set():
        sleep(0.05) #TODO: this has to be small enough to parse input in real time, or else a time delay will slowly unfold
        try:
            line = sio.readline()

            try:
                msg = pynmea2.parse(line)
            except serial.SerialException as e:
                print('Device error: {}'.format(e))
                continue
            except pynmea2.ParseError as e:
                print('Parse error: {}'.format(e))
                continue

            #only parse nmea messages that comprise GPS information
            if msg and hasattr(msg, 'lat') and hasattr(msg, 'lon'):
                #get latitude and longitude (access values as decimal degreed instead of NMEA format)
                #which is DDDMM.MMMM (degrees, minutes, seconds)
                lat = msg.latitude 
                lon = msg.longitude

                if lat != 0.0 or lon != 0.0:
                    _gps_available = True

                    # print(f"lat:{lat} lon:{lon}")
                    _lock.acquire()
                    _current_position = lat, lon
                    _lock.release()

                else:
                    _gps_available = False
        except serial.SerialException as e:
            print(f"Device error: {e}")
            break
        except ChecksumException as e:
            print(f"Parse error: {e}")
            continue
        except UnicodeDecodeError as e:
            print(f"Unicode error: {e}")
            continue

gps_thread = None
def start_gps_tracking():
    global gps_thread #because new thread instance is assigned to this variable
    if gps_is_running():
        print("[*] Tried starting gps thread although there is already one running.")
    _stop_event.clear()

    print("[*] Starting GPS Thread")
    gps_thread = Thread(target=_read_data, name="gps tracker")
    gps_thread.daemon = True
    gps_thread.start()

def stop_gps_tracking():
    global _gps_available
    _stop_event.set()
    gps_thread.join()
    print("[+] Stopped GPS Thread")
    _gps_available = False

def gps_is_running():
    return not _stop_event.is_set()


#some tests
def test_tracking():
    print("[*] Starting ... there should be some output")
    start_gps_tracking()
    sleep(8)
    pos = get_gps_data()
    print(f"{pos[0]} {pos[1]}")
    sleep(5)
    stop_gps_tracking()
    print("[*] Stopped ... there should be no more output")
    sleep(5)

def test_waypoints():
    route = GPSRoute("test route", filepath="test.txt")
    pts =   [[49.77972716666667,11.177007666666666],
            [49.779736,11.176986],
            [49.779742166666665,11.176971666666667],
            [49.77974716666667,11.1769645],
            [49.779753,11.176962166666666],
            [49.7797615,11.176964833333333],
            [49.77976433333333,11.176968333333333],
            [49.779763333333335,11.176972333333334],
            [49.77975966666666,11.176979333333334],
            [49.77975683333333,11.176987]]
    for pt in pts:
        route.add_waypoint(pt[0], pt[1])
    print(route.store_as_file())

def test_load(filename):
    route = GPSRoute("test route", filepath=filename)
    route.load_from_file()
    print(route.get_gpx())

def test_track():
    route = GPSRoute("test route", "blub.txt")
    route.start_capture()
    sleep(5)
    route.stop_capture()

def test_checksum():
    return check_gga_checksum("$GNGGA,160112.000,4936.10701,N,01100.40540,E,1,08,1.5,330.8,M,47.2,M,,*48", "48")

if __name__ == "__main__":
    test_checksum()
