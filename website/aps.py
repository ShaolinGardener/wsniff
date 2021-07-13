from threading import Thread, Event, Lock
from time import sleep
import os

from scapy.all import *

aps = dict() #all APs that are uncovered

#used to synchronize
_running = Event()
#lock is not really needed here because there is just one thread writing and one reading
lock = Lock()

def hopper(iface):
    channel = 1
    stop_hopper = False
    while _running.is_set():
        time.sleep(0.25)
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

            #lock.acquire()
            aps[bssid] = (bssid, ssid, channel)
            #lock.release()
            
            #hidden networks
            if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
               print("[+] Hidden Network Detected")
            #print("[+] AP detected: %s" % (ssid))


def scan(iface):
    while _running.is_set():
        print("hey i am antonia")
        sniff(iface=iface, prn=handlePacket, count=5, timeout=2)


    

def start_scan(interface="wlan1mon"):
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