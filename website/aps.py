from threading import Thread, Event, Lock
from time import sleep
import time
import random, os
import website.oui as oui
from website.dot11.frame import Frame 

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


#to prevent race conditions
lock = Lock() 

#bssid as unique identifier, AccessPoint object as value
# bssid: str -> ap: AcessPoint
aps = dict() #all APs that are uncovered 

# bssid: str -> # station-MAC: str ; e.g. {"bc:30:d9:33:30:ca" : "e8:df:70:f8:32:80"}
ap_station_mapper = dict() #assign stations to access points

# bssid: str -> station: Station
stations = dict() #all Stations
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
        f = Frame(pkt)
        
        print(f)

def scan(iface):
    while _running.is_set():
        sniff(iface=iface, prn=handlePacket, count=5, timeout=2)
    #because stop_scan can run through before while loop, access points can be added to aps after _running has been unset
    #therefore it is necessary to call clear exactly here
    aps.clear()


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