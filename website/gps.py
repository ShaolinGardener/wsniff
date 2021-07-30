import io, json

import pynmea2
import serial
from datetime import datetime

from time import sleep, mktime, time
from website.settings import GPS_SERIAL

from threading import Thread, Event, Lock

#Serial baud rate of neo 8M: 9600Bd (baud rate ist die symbolrate, also anzahl uebertragene zeichen pro sekunde)
ser = serial.Serial(GPS_SERIAL, 9600, timeout=5.0) #'/dev/serial0'

#nmea protokoll def. <CR><LF> als ende zeile -> TextIOWrapper wandelt das automatisch in \n um
sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser))

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

_stop_event = Event()
_stop_event.set()
_lock = Lock()
_current_position = (0.0, 0.0)
_gps_available = False

def _read_data():
    global _current_position
    global _gps_available

    while not _stop_event.is_set():
        sleep(0.1) #TODO: this has to be small enough to parse input in real time, or else a time delay will slowly unfold
        try:
            line = sio.readline()
            #print(line)
            
            if line.startswith("$GNGGA"):  
                gpsdata = pynmea2.parse(line)  
                num_sats = gpsdata.num_sats #str
                if int(num_sats) > 0: 
                    _gps_available = True

                    lat, lon = gpsdata.latitude, gpsdata.longitude
                    time = gpsdata.timestamp #type: datetime.time class
                    print(f"{time} {num_sats} {gpsdata.altitude}")
                    _lock.acquire()
                    _current_position = lat, lon
                    _lock.release()

                    #uncommenting the following 3 lines you can copy the output into google and look up the location there
                    #lat = '%02d°%02d′%07.4f″' % (gpsdata.latitude, gpsdata.latitude_minutes, gpsdata.latitude_seconds)
                    #lon = '%02d°%02d′%07.4f″' % (gpsdata.longitude, gpsdata.longitude_minutes, gpsdata.longitude_seconds)
                    #print(f"{lat} {lon}")
                else:
                    _gps_available = False
        except serial.SerialException as e:
            print(f"Device error: {e}")
            break
        except pynmea2.ParseError as e:
            print(f"Parse error: {e}")
            continue

def is_gps_available():
    global _gps_available
    return _gps_available

def get_gps_data():
    _lock.acquire()
    lat, lon = _current_position[0], _current_position[1]
    _lock.release()
    return lat, lon


def start_gps_tracking():
    _stop_event.clear()
    
    print("[*] Starting GPS Thread")
    thread = Thread(target=_read_data, name="gps tracker")
    thread.daemon = True
    thread.start()

def stop_gps_tracking():
    global _gps_available
    _stop_event.set()
    _gps_available = False

def gps_is_running():
    return not _stop_event.is_set()

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

if __name__ == "__main__":
    test_track()
