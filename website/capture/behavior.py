from abc import ABC, abstractmethod
from threading import Thread, Event, Lock
from time import sleep, time
from datetime import datetime

from website import app, db
from website.models import Discovery, FullCapture, Map
from website.interfaces import Interface
import website.gps as gps
import website.oui as oui
from website.interfaces import Interface, get_interfaces, Mode
from website.capture.hopper import Hopper, HoppingStrategy, EvenlyDistributedHopping
from website.api import upload_discovery

import display.display as display

import os

from scapy.all import *



class CaptureBehavior(ABC):
    """
    abstract base class for defining the capturing behavior of a capture
    """

    
    def init(self, capture):
        """
        important: called by a freshly created Capture-object cause both that and this object need a reference to each other
        """
        self.capture = capture
    
    def configure(self, options:dict):
        self.options = options

    @abstractmethod
    def handle_packet(self, frame):
        """
        Be aware that if using multiple interfaces, this method will be called concurrently.
        So make sure it is implemented thread-safe in your concrete Behavior classes.
        """
        pass

    #hook methods
    
    def start_capture(self):
        """
        called before first frame is captured
        """
        pass

    
    def stop_capture(self):
        """
        called after last frame has been captured
        """
        pass


class TestBehavior:
    """
    do not capture any packets
    """ 
    
    def handle_packet(self, frame):
        pass


class CaptureAllBehavior(CaptureBehavior):
    """
    write all frames into a .pcap
    """

    def __init__(self, cap: FullCapture):
        """
        cap: the database object representing this capture
            Stores all the information needed for this capture behavior
        """
        #TODO: enable support for multiple channels
        self.channels = cap.get_channels()

        self.gps_tracking = cap.gps_tracking
        self.dir_path = cap.get_dir_path()
        self.lock = Lock()

    def start_capture(self):
        #set all interfaces to the specified channel
        for i in range(min(len(self.channels), len(self.capture.interfaces))):
            self.capture.interfaces[i].set_channel(self.channels[i])

        #create directory for files that belong to this capture
        os.makedirs(self.dir_path)

        #to enable multiple channels: implement CaptureThread class in capture.py and
        #give each thread an id: then each thread should have its own PcapWriter
        self.pcap_filepath = os.path.join(self.dir_path, "cap.pcap")
        self.packet_writer = PcapWriter(self.pcap_filepath,
                                        append=True, sync=True)

        #gps
        if self.gps_tracking: #TODO: name of route using db to query for capture title maybe?
            path = os.path.join(self.dir_path, "gps.txt")
            self.gps_route = gps.GPSRoute(str(id), path)

        #do this in the end (that's why we use an additional if-clause since there could be isnerted new code above later on)
        if self.gps_tracking:
            self.gps_route.start_capture()

    def stop_capture(self):
        if self.gps_tracking:
            self.gps_route.stop_capture()

    def handle_packet(self, frame):
        self.lock.acquire()
        self.packet_writer.write(frame)
        self.capture.num_packets += 1
        self.lock.release()
        
#BEGIN OF MapAccessPointsBehavior
class _AccessPoint():
        def __init__(self, bssid, ssid, channel, encryption):
            self.bssid = bssid
            self.ssid = ssid
            self.channel = channel
            self.encryption = encryption
            self.signal_strength = 0

            self.lock = Lock()
            #gps coordinates
            self.lat, self.lon = gps.get_gps_data()

            self.t_last_seen = time.time()
        
        def isAlive(self, t_death):
            return time.time() - self.t_last_seen < t_death

        def refresh(self, signal_strength=0):
            #only store new gps coordinates if signal is stronger than last time
            if signal_strength > self.signal_strength:
                self.lock.acquire()
                self.t_last_seen = time.time()
                self.signal_strength = signal_strength
                #get new gps coordinates and update them
                self.lat, self.lon = gps.get_gps_data()
                self.lock.release()

        def __str__(self):
            return f"[{self.bssid}] {self.ssid} on channel {self.channel}"

       
class MapAccessPointsBehavior(CaptureBehavior):
    """
    can be used to create a map of access points / wardriving
    """  
    
    def __init__(self, map: Map):
        #the 802.11 channels to observe 
        self.channels = map.get_channels()

        #bssid as unique identifier, AccessPoint object as value
        # bssid: str -> ap: AcessPoint
        self.aps = dict() #all APs that are uncovered 
        self._running = Event() #used to synchronize
        self.lock = Lock() 

        self.map = map

        self.num_aps = 0


    def start_capture(self):

        #hop through channels - hopping thread
        hopping_strategy = EvenlyDistributedHopping(delay=0.25)
        self.hopper = Hopper(hopping_strategy, self.capture.interfaces, self.channels)
        self.hopper.start() 

        #cleaning thread
        cleaning_thread = Thread(target=self.clean, name="cleaner")
        self.cleaning_thread = cleaning_thread #we need a reference to stop thread later on
        cleaning_thread.daemon = True
        cleaning_thread.start()


    def add_discovery(self, ap: _AccessPoint):
        """
        Adds AP discovery to database
        """
        d = Discovery(mac=ap.bssid)
        d.ssid=ap.ssid
        d.channel=ap.channel
        d.signal_strength=ap.signal_strength 
        d.gps_lat=ap.lat
        d.gps_lon=ap.lon
        d.encryption = ap.encryption
        d.timestamp = datetime.fromtimestamp(ap.t_last_seen)
        #somehow d.map = self.map fails
        d.map_id = self.map.id

        try:
            db.session.add(d)
            db.session.commit()
            return d
        except:
            print("[-] Adding discovery to DB failed.")
            return None

    def clean(self, t_remove=180, t_sleep=30):
        """
        t_remove: if no beacon frame of a specific access point is received within this time frame, it is removed from the dict and written to file
        t_sleep: timespan between cleaning traversals
        """
        while self._running.is_set():
            sleep(t_sleep)
            
            #remove all dead access points and add them to the database
            bssids = tuple(self.aps.keys())
            for bssid in bssids:
                if not self.aps[bssid].isAlive(t_remove):
                    ap = self.aps[bssid]
                    self.add_discovery(ap)
                    del self.aps[bssid]


    def handle_packet(self, frame):
        self.lock.acquire()
        self.capture.num_packets += 1
        self.lock.release()

        if frame.haslayer(Dot11Beacon):
            #bssid of AP is stored in second address field of header
            bssid = frame.getlayer(Dot11).addr2

            #found new access point: add it to dict
            if bssid not in self.aps:

                ssid = frame.getlayer(Dot11Elt).info.decode("utf-8")
                channel = frame.getlayer(Dot11Elt).channel
                stats = frame[Dot11Beacon].network_stats()
                encryption = stats.get("crypto").pop()
                ap = _AccessPoint(bssid, ssid, channel, encryption)

                if frame.haslayer(RadioTap):
                    ap.signal_strength = frame[RadioTap].dBm_AntSignal

                #checking and adding ap to dict has to be an atomic action
                #FIXME: we are doing a double check here to increase performance,
                #however if the condition evaluates to False here, the else branch won't
                #be executed
                self.lock.acquire()
                if bssid not in self.aps:
                    self.aps[bssid] = ap
                    self.num_aps += 1
                    #update channel stats of hopper
                    self.hopper.increment_ap_observations(channel)
                self.lock.release()
            else: #acess point already in dict -> refresh AP to prevent it from getting deleted
                #acess point already in dict -> refresh AP to prevent it from getting deleted
                if not frame.haslayer(RadioTap): 
                    self.aps[bssid].refresh()
                else:
                    signal_strength = frame[RadioTap].dBm_AntSignal
                    self.aps[bssid].refresh(signal_strength)

    def stop_capture(self):
        #stop thread
        self._running.clear()
        self.hopper.stop_hopping()
        self.cleaning_thread.join()

        #store APs in DB if not done so before
        for bssid in self.aps:
            ap = self.aps[bssid]
            d = self.add_discovery(ap)
        #clear dict
        self.aps.clear()

        print("[+] Finished wardriving activity.")


class OnlineMapBehavior(CaptureBehavior):
    """
    Use the sniffer to contribute to an online map
    """  
    
    def __init__(self, map:Map):
        #the 802.11 channels to observe 
        self.channels = map.get_channels()
        
        #bssid as unique identifier, AccessPoint object as value
        #bssid: str -> ap: AcessPoint
        self.aps = dict() #all APs that are uncovered 
        self._running = Event() #used to synchronize
        self.lock = Lock() 

        self.map = map

        self.num_aps = 0


    def start_capture(self):

        #hop through channels - hopping thread
        hopping_strategy = EvenlyDistributedHopping(delay=0.25)
        self.hopper = Hopper(hopping_strategy, self.capture.interfaces, self.channels)
        self.hopper.start()

        #cleaning thread
        cleaning_thread = Thread(target=self.clean, name="cleaner")
        self.cleaning_thread = cleaning_thread #we need a reference to stop thread later on
        cleaning_thread.daemon = True
        cleaning_thread.start()

    def add_discovery(self, ap: _AccessPoint):
        """
        Adds AP discovery to database
        """
        d = Discovery(mac=ap.bssid)
        d.ssid=ap.ssid
        d.channel=ap.channel
        d.signal_strength=ap.signal_strength 
        d.gps_lat=ap.lat
        d.gps_lon=ap.lon
        d.encryption = ap.encryption
        d.timestamp = datetime.fromtimestamp(ap.t_last_seen)
        d.map = self.map
        
        try:
            db.session.add(d)
            db.session.commit()
            return d
        except:
            print("[-] Adding discovery to DB failed.")
            return None


    def clean(self, t_remove=180, t_sleep=30):
        """
        t_remove: if no beacon frame of a specific access point is received within this time frame, it is removed from the dict and written to file
        t_sleep: timespan between cleaning traversals
        """
        while self._running.is_set():
            sleep(t_sleep)
            
            #remove all dead access points and add them to the database
            bssids = tuple(self.aps.keys())
            for bssid in bssids:
                if not self.aps[bssid].isAlive(t_remove):
                    ap = self.aps[bssid]
                    self.add_discovery(ap)
                    del self.aps[bssid]


    def handle_packet(self, frame):
        self.lock.acquire()
        self.capture.num_packets += 1
        self.lock.release()

        if frame.haslayer(Dot11Beacon):
            #bssid of AP is stored in second address field of header
            bssid = frame.getlayer(Dot11).addr2

            #found new access point: add it to dict
            if bssid not in self.aps:

                ssid = frame.getlayer(Dot11Elt).info.decode("utf-8")
                channel = frame.getlayer(Dot11Elt).channel
                stats = frame[Dot11Beacon].network_stats()
                encryption = stats.get("crypto").pop()
                ap = _AccessPoint(bssid, ssid, channel, encryption)

                if frame.haslayer(RadioTap):
                    ap.signal_strength = frame[RadioTap].dBm_AntSignal

                #FIXME: if the check evaluates to False, the else branch wont be executed
                #although it should
                self.lock.acquire()
                if bssid not in self.aps:
                    self.aps[bssid] = ap
                    self.num_aps += 1
                    #update channel stats of hopper
                    self.hopper.increment_ap_observations(channel)
                self.lock.release() 
            else: #acess point already in dict -> refresh AP to prevent it from getting deleted
                #acess point already in dict -> refresh AP to prevent it from getting deleted
                if not frame.haslayer(RadioTap): 
                    self.aps[bssid].refresh()
                else:
                    signal_strength = frame[RadioTap].dBm_AntSignal
                    self.aps[bssid].refresh(signal_strength)

    def stop_capture(self):
        #stop thread
        self._running.clear()
        self.hopper.stop_hopping()
        self.cleaning_thread.join()

        #store APs in DB if not done so before
        for bssid in self.aps:
            ap = self.aps[bssid]
            d = self.add_discovery(ap)
        #clear dict
        self.aps.clear()

        #try to upload all discoveries to server
        discoveries = self.map.discoveries
        for discovery in discoveries:
            upload_discovery(discovery)
        
        print("[+] Finished wardriving activity.")
