from threading import Thread, Event, Lock
from time import sleep
import time
import random, os
import website.oui as oui
from website.dot11.frame import Frame 
import website.gps as gps

from scapy.all import *





#to prevent race conditions
lock = Lock() 






#TODO modify this to remove APs after a few minutes + write infos down in file
def clean(t_remove, t_sleep=30):
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
        




def handlePacket(pkt):
    
    
            
        # #hidden networks
        # if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
        #    print("[+] Hidden Network Detected")
        # #print("[+] AP detected: %s" % (ssid))
    

        





def start_scan(interface:str, t_remove:int=180, t_clean=7):
    """
    t_remove: if the access point has not been seen for this time, it is removed from the list of active access points
    t_clean: time span between two iterations of the cleaning thread
    """

    #TODO: replace with thread which periodically just writes out all access points, clears the dict and then continues
    #remove old AccessPoints 
    # thread = Thread(target=clean, args=(t_remove, t_clean), name="cleaner")
    # thread.daemon = True
    # thread.start()



    

