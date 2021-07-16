from threading import Thread, Event, Lock
from time import sleep, time
import random, os

from scapy.all import *


class AccessPoint():

    def __init__(self, bssid, ssid, channel):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel

        self.t_last_seen = time()
    
    def isAlive(self, t_death=20):
        return time() - self.t_last_seen < t_death

    def refresh(self):
        self.t_last_seen = time

    def __str__(self):
        return f"[{self.bssid}] {self.ssid} on channel {self.channel}"


#bssid as unique identifier, AccessPoint object as value
lock = Lock() #lock is not really needed here because there is just one thread writing and one reading
aps = dict() #all APs that are uncovered
_running = Event() #used to synchronize


def print_access_points():
    for ap in aps.values():
        print(ap)

def clean(t_remove, t_sleep=30):
    while _running.is_set():
        sleep(t_sleep)
        
        #remove all dead access points
        bssids = tuple(aps.keys())
        for bssid in bssids:
            if not aps[bssid].isAlive(t_remove):
                del aps[bssid]
        

def found_access_point(bssid, ssid, channel):
    #found new access point: add it to dict
    if bssid not in aps:
        ap = AccessPoint(bssid, ssid, channel)
        aps[bssid] = ap
    else:
        #acess point already in dict -> refresh AP to prevent it from getting deleted
        aps[bssid].refresh()



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

        if bssid not in aps:
            ssid = pkt.getlayer(Dot11Elt).info.decode("utf-8")
            channel = pkt.getlayer(Dot11Elt).channel

            found_access_point(bssid, ssid, channel)
            
            #hidden networks
            if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
               print("[+] Hidden Network Detected")
            #print("[+] AP detected: %s" % (ssid))


def scan(iface):
    while _running.is_set():
        print("hey i am antonia")
        sniff(iface=iface, prn=handlePacket, count=5, timeout=2)


    

def start_scan(t_remove: int, interface:str="wlan1mon"):
    """
    t_remove: if the access point has not been seen for this time, it is removed from the list of active access points
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
    thread = Thread(target=scan, args=(interface, ), name="scanner")
    thread.daemon = True
    thread.start()

    #remove old AccessPoints 
    thread = Thread(target=clean, args=(t_remove, ), name="cleaner")
    thread.daemon = True
    thread.start()

def stop_scan():
    _running.clear()
    aps.clear() #clear results from previous scan

def get_aps():
    #lock.acquire()
    copy = aps.copy()
    #lock.release()
    return copy


if __name__ == "__main__":
    start_scan()
    sleep(2)
    t = get_aps()
    for ap in t:
        print(ap, t[ap])
    sleep(7)
    t = get_aps()
    for ap in t:
        print(ap)

    stop_scan()