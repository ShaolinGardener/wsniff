from threading import Thread, Event, Lock
from time import sleep
import time
import random, os
import website.oui as oui
#from website.frame import Frame

from scapy.all import *


class AccessPoint():

    def __init__(self, bssid, ssid, channel):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.signal_strength = 0

        self.t_last_seen = time.time()

    def isAlive(self, t_death=20):
        return time.time() - self.t_last_seen < t_death

    def refresh(self, signal_strength=0):
        self.t_last_seen = time.time()

        if signal_strength != 0:
            self.signal_strength = signal_strength


    def __str__(self):
        return f"[{self.bssid}] {self.ssid} on channel {self.channel}"


class Station:
    def __init__(self, mac, bssid):
        self.bssid = bssid
        self.mac = mac
        self.signal_strength = 0

        self.t_last_seen = time.time()

class Frame:
    """
    Format that is more intuitive to use (also reduces coupling because we are now more independant from other libraries, so
    it is easer to switch them)
    """

    TO_DS = 0x1
    FROM_DS = 0x2
    DOT11_FRAME_TYPE_MANAGEMENT = 0
    DOT11_FRAME_TYPE_CONTROL = 1
    DOT11_FRAME_TYPE_DATA = 2

    def __init__(self, frame, channel=0, iface=None):
        self.frame = frame

        self.bssid = None
        self.ssid = None
        self.signal_strength = 0
        self.channel = channel
        self.iface = iface
        self.frame_bytes = len(frame)

        #FC: frame control
        to_ds = frame.FCfield & Frame.TO_DS != 0
        from_ds = frame.FCfield & Frame.FROM_DS != 0
        if to_ds and from_ds:
            self.dst = frame.addr3
            self.src = frame.addr4
            self.macs = {frame.addr1, frame.addr2, frame.addr3, frame.addr4}
        elif to_ds:
            self.src = frame.addr2
            self.dst = frame.addr3
            self.bssid = frame.addr1
            self.macs = {frame.addr2, frame.addr3}
        elif from_ds:
            self.src = frame.addr3
            self.dst = frame.addr1
            self.bssid = frame.addr2
            self.macs = {frame.addr1, frame.addr3}
        else:
            self.dst = frame.addr1
            self.src = frame.addr2
            self.bssid = frame.addr3
            self.macs = {frame.addr1, frame.addr2}

        if (frame.haslayer(scapy.Dot11Elt) and
                (frame.haslayer(scapy.Dot11Beacon) or frame.haslayer(scapy.Dot11ProbeResp))):

            try:
                self.ssid = frame[scapy.Dot11Elt].info.decode().replace("\x00", "[none]")
            except UnicodeDecodeError:
                # Only seems to happen on macOS - probably some pcap decoding bug
                self.ssid = None

        if frame.haslayer(scapy.RadioTap):
            #old solution: https://stackoverflow.com/questions/10818661/scapy-retrieving-rssi-from-wifi-packets
            #has been fixed now you don't have to use decoded part of packet but can use dBm_AntSignal
            self.signal_strength = frame[scapy.RadioTap].dBm_AntSignal



#to prevent race conditions
lock = Lock()

#bssid as unique identifier, AccessPoint object as value
# bssid: str -> ap: AcessPoint
aps = dict() #all APs that are uncovered

# bssid: str -> # station-MACs: lsit ; e.g. {"bc:30:d9:33:30:ca" : ["e8:df:70:f8:32:80", "e4:df:70:f8:32:80"]}
ap_station_mapper = dict() #assign stations to access points

# bssid: str -> station: Station
stations = dict() #all Stations --- NOT USED RIGHT NOW!

_running = Event() #used to synchronize


def print_access_points():
    for ap in aps.values():
        print(ap)

def clean(t_remove, t_sleep=10):
    """
    t_remove: if no beacon frame of a specific access point is received within this time frame, it is removed from the list
    t_sleep: timespan between cleaning traversals
    """
    while _running.is_set():
        sleep(t_sleep)

        #remove all dead access points
        bssids = tuple(aps.keys())
        for bssid in bssids:
            if not aps[bssid].isAlive(t_remove):
                del aps[bssid]



def hopper(iface):
    channel = 1
    stop_hopper = False
    while _running.is_set():
        sleep(0.25)
        os.system(f"sudo iwconfig {iface} channel {channel}")
        #print(f"[*] current channel {channel}")

        dig = int(random.random() * 13) + 1
        if dig != channel:
            channel = dig


def handlePacket(pkt):

    if pkt.haslayer(Dot11Beacon):
        #bssid of AP is stored in second address field of header
        bssid = pkt.getlayer(Dot11).addr2

        #found new access point: add it to dict
        if bssid not in aps:
            ssid = pkt.getlayer(Dot11Elt).info.decode("utf-8")
            channel = pkt.getlayer(Dot11Elt).channel
            ap = AccessPoint(bssid, ssid, channel)

            if pkt.haslayer(RadioTap):
                ap.signal_strength = pkt[RadioTap].dBm_AntSignal

            aps[bssid] = ap
        else: #acess point already in dict -> refresh AP to prevent it from getting deleted
            #acess point already in dict -> refresh AP to prevent it from getting deleted
            if not pkt.haslayer(RadioTap):
                aps[bssid].refresh()
            else:
                signal_strength = pkt[RadioTap].dBm_AntSignal
                aps[bssid].refresh(signal_strength)

        # #hidden networks
        # if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
        #    print("[+] Hidden Network Detected")
        # #print("[+] AP detected: %s" % (ssid))
    else:
        a1 = pkt.getlayer(Dot11).addr1
        a2 = pkt.getlayer(Dot11).addr2
        a3 = pkt.getlayer(Dot11).addr3
        a4 = pkt.getlayer(Dot11).addr4
        #print(f"{a1} {a2} {a3} {a4}")

        f = Frame(pkt)
        #print(f)

        #von ap to station
        if f.bssid and f.dst != "ff:ff:ff:ff:ff:ff":  #and f.frame_type == Frame.DOT11_FRAME_TYPE_DATA:
            station = f.dst
            ap = f.src
            #print(f"AP->STA station: {station}")
            if ap not in ap_station_mapper:
                ap_station_mapper[ap] = set()
            ap_station_mapper[ap].add(station)

        elif f.src and f.src != "ff:ff:ff:ff:ff:ff": #from station to ap
            #TODO: sometimes (control frames) the src is actually an AP although there is no bssid
            station = f.src
            ap = f.dst
            #print(f"STA->AP station {station}")
            if ap not in ap_station_mapper:
                ap_station_mapper[ap] = set()
            ap_station_mapper[ap].add(station)



def scan(iface):
    while _running.is_set():
        sniff(iface=iface, prn=handlePacket, count=5, timeout=2)
    #because stop_scan can run through before while loop, access points can be added to aps after _running has been unset
    #therefore it is necessary to call clear exactly here
    aps.clear()
    ap_station_mapper.clear()


def detection_is_running():
    return _running.is_set()

def start_scan(interface:str, t_remove:int=23, t_clean=7):
    """
    t_remove: if the access point has not been seen for this time, it is removed from the list of active access points
    t_clean: time span between two iterations of the cleaning thread
    """
    #already running
    if _running.is_set():
        raise ValueError(f"Already started AP scan.")
    _running.set()

    #hop through channels
    thread = Thread(target=hopper, args=(interface, ), name="hopper")
    thread.daemon = True
    thread.start()

    #scan packets to find beacon frames
    thread = Thread(target=scan, args=(interface,), name="scanner")
    thread.daemon = True
    thread.start()

    #remove old AccessPoints
    thread = Thread(target=clean, args=(t_remove, t_clean), name="cleaner")
    thread.daemon = True
    thread.start()

def stop_scan():
    _running.clear()
    aps.clear() #clear results from previous scan (this is also done in the scan function and necessary there, but for logical reasons also included here)


def get_aps():
    """
    get list of aps
    format: (bssid, ssid, channel, vendor)
    """
    #lock.acquire()
    copy = aps.copy()
    #lock.release()
    res = [(ap.bssid, ap.ssid, ap.channel, ap.signal_strength, oui.lookup(ap.bssid)) for ap in copy.values()]
    res.sort(key=lambda ap: ap[3], reverse=True) #sort according to signal streng in desc order
    return res

def get_stations_for(bssid):
    stations = ap_station_mapper.get(bssid)
    if stations:
        return list(stations)
    return []


if __name__ == "__main__":
    start_scan(interface="wlan1mon", t_remove=0.5, t_clean=2)
    sleep(2)
    t = get_aps()
    for ap in t:
        print(ap)
    sleep(7)

    print("[+] Seven seconds later:")
    t = get_aps()
    for ap in t:
        print(ap)

    stop_scan()
