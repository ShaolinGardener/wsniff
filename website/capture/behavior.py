from abc import ABC, abstractmethod
from threading import Thread, Event, Lock
from time import sleep, time

from website import app, db
from website.models import Discovery, Map
from website.interfaces import Interface
import website.gps as gps
import website.oui as oui
from website.interfaces import Interface, get_interfaces, Mode
from website.capture.hopper import Hopper, HoppingStrategy, EvenlyDistributedHopping

import display.display as display

import os, random

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

    def __init__(self, channel, gps_tracking):
        self.channel = channel
        self.gps_tracking = gps_tracking

    def start_capture(self):
        self.capture.interface.set_channel(self.channel)

        self.pcap_filepath = os.path.join(self.capture.dirpath, "cap.pcap")
        self.packet_writer = PcapWriter(self.pcap_filepath,
                                        append=True, sync=True)

        if self.gps_tracking: #TODO: name of route using db to query for capture title maybe?
            path = os.path.join(self.capture.dirpath, "gps.txt")
            self.gps_route = gps.GPSRoute(str(id), path)

        #do this in the end (that's why we use an additional if-clause since there could be isnerted new code above later on)
        if self.gps_tracking:
            self.gps_route.start_capture()

    def stop_capture(self):
        if self.gps_tracking:
            self.gps_route.stop_capture()

    def handle_packet(self, frame):
        self.packet_writer.write(frame)
        self.capture.num_packets += 1
        
#BEGIN OF MapAccessPointsBehavior
class _AccessPoint():
        def __init__(self, bssid, ssid, channel):
            self.bssid = bssid
            self.ssid = ssid
            self.channel = channel
            self.signal_strength = 0
            #gps coordinates
            self.lat, self.lon = gps.get_gps_data()

            self.t_last_seen = time.time()
        
        def isAlive(self, t_death):
            return time.time() - self.t_last_seen < t_death

        def refresh(self, signal_strength=0):
            #only store new gps coordinates if signal is stronger than last time
            if signal_strength > self.signal_strength:
                self.t_last_seen = time.time()
                self.signal_strength = signal_strength
                #get new gps coordinates and update them
                self.lat, self.lon = gps.get_gps_data()

        def __str__(self):
            return f"[{self.bssid}] {self.ssid} on channel {self.channel}"

       
class MapAccessPointsBehavior(CaptureBehavior):
    """
    can be used to create a map of access points / wardriving
    """  
    
    def __init__(self):
        #bssid as unique identifier, AccessPoint object as value
        # bssid: str -> ap: AcessPoint
        self.aps = dict() #all APs that are uncovered 
        self._running = Event() #used to synchronize
        self.lock = Lock() 

        self.num_aps = 0


    def start_capture(self):
        self.filepath = os.path.join(self.capture.dirpath, "wardrive.txt")

        #hop through channels - hoppin thread
        self._running.set()
        interface = self.capture.interface.get_name()
        hopping_thread = Thread(target=self.hopper, args=(interface, ), name="hopper")
        self.hopping_thread = hopping_thread #we need a reference to stop thread later on
        hopping_thread.daemon = True
        hopping_thread.start()

        #cleaning thread
        cleaning_thread = Thread(target=self.clean, name="cleaner")
        self.cleaning_thread = cleaning_thread #we need a reference to stop thread later on
        cleaning_thread.daemon = True
        cleaning_thread.start()

       

    def hopper(self, iface):
        channel = 1
        stop_hopper = False
        while self._running.is_set():
            sleep(0.25)
            os.system(f"sudo iwconfig {iface} channel {channel}")
            #print(f"[*] current channel {channel}")
            
            dig = int(random.random() * 13) + 1
            if dig != channel:
                channel = dig

    def clean(self, t_remove=180, t_sleep=30):
        """
        t_remove: if no beacon frame of a specific access point is received within this time frame, it is removed from the dict and written to file
        t_sleep: timespan between cleaning traversals
        """
        while self._running.is_set():
            sleep(t_sleep)
            
            with open(self.filepath, "a")  as f: #now add new information to file
                #remove all dead access points
                bssids = tuple(self.aps.keys())
                for bssid in bssids:
                    if not self.aps[bssid].isAlive(t_remove):
                        ap = self.aps[bssid]
                        line = f"{ap.t_last_seen};{ap.bssid};{ap.ssid};{ap.channel};{ap.signal_strength};{oui.lookup(ap.bssid)};{ap.lat};{ap.lon}\n" 
                        f.write(line)
                        del self.aps[bssid]


    def handle_packet(self, frame): 
        self.capture.num_packets += 1

        if frame.haslayer(Dot11Beacon):
            #bssid of AP is stored in second address field of header
            bssid = frame.getlayer(Dot11).addr2 

            #found new access point: add it to dict
            if bssid not in self.aps:
                self.num_aps += 1

                ssid = frame.getlayer(Dot11Elt).info.decode("utf-8")
                channel = frame.getlayer(Dot11Elt).channel
                ap = _AccessPoint(bssid, ssid, channel)

                if frame.haslayer(RadioTap):   
                    ap.signal_strength = frame[RadioTap].dBm_AntSignal

                self.aps[bssid] = ap
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
        self.hopping_thread.join()
        self.cleaning_thread.join()

        #store in file   
        f = open(self.filepath, "a") 
        for bssid in self.aps:
            #better to read here than f"-Syntax
            ap = self.aps[bssid]
            line = f"{ap.t_last_seen};{ap.bssid};{ap.ssid};{ap.channel};{ap.signal_strength};{oui.lookup(ap.bssid)};{ap.lat};{ap.lon}\n" 
            f.write(line)

        f.close()
        self.aps.clear()
        print("end bahavior")


class OnlineMapBehavior(CaptureBehavior):
    """
    Use the sniffer to contribute to an online map
    """  
    
    def __init__(self, map:Map):
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
        available_interfaces = get_interfaces(Mode.MONITOR)
        self.hopper = Hopper(hopping_strategy, available_interfaces, list(range(1, 14)))
        self.hopper.start()

        #cleaning thread
        cleaning_thread = Thread(target=self.clean, name="cleaner")
        self.cleaning_thread = cleaning_thread #we need a reference to stop thread later on
        cleaning_thread.daemon = True
        cleaning_thread.start()

    def add_discovery(self, ap):
        """
        Adds AP discovery to database
        """
        d = Discovery(mac=ap.bssid)
        d.ssid=ap.ssid
        d.channel=ap.channel
        d.signal_strength=ap.signal_strength 
        d.gps_lat=ap.lat
        d.gps_lon=ap.lon
        d.encryption = 1
        d.map = self.map
        #ap.t_last_seen

        try:
            db.session.add(d)
            db.session.commit()
        except:
            print("[-] Adding discovery to DB failed.")


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
        self.capture.num_packets += 1

        if frame.haslayer(Dot11Beacon):
            #bssid of AP is stored in second address field of header
            bssid = frame.getlayer(Dot11).addr2 

            #found new access point: add it to dict
            if bssid not in self.aps:
                self.num_aps += 1

                ssid = frame.getlayer(Dot11Elt).info.decode("utf-8")
                channel = frame.getlayer(Dot11Elt).channel
                ap = _AccessPoint(bssid, ssid, channel)

                if frame.haslayer(RadioTap):   
                    ap.signal_strength = frame[RadioTap].dBm_AntSignal

                self.aps[bssid] = ap

                #update channel stats of hopper
                self.hopper.increment_ap_observations(channel)
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

        #store in DB
        for bssid in self.aps:
            #better to read here than f"-Syntax
            ap = self.aps[bssid]
            self.add_discovery(ap)

        #try to upload data to server (using multiple TAs)
        #FIXME

        self.aps.clear()
        print("[+] Finished wardriving activity.")
