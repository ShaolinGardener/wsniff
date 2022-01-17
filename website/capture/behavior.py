from website import app, db
from website.models import Discovery, Capture, FullCapture, Map, CaptureAttribute, AttributeType
from website.interfaces import Interface
import website.gps as gps
import website.oui as oui
from website.interfaces import Interface, get_interfaces, Mode
from website.capture.hopper import Hopper, HoppingStrategy, EvenlyDistributedHopping
from website.api import upload_discovery

import display.display as display

import os
from abc import ABC, abstractmethod
from threading import Thread, Event as ThreadEvent, Lock as ThreadLock
from multiprocessing import Lock as ProcessLock, Manager
from time import sleep, time
from datetime import datetime
import logging

from scapy.all import *



class CaptureBehavior(ABC):
    """
    abstract base class for defining the capturing behavior of a capture
    """

    def __init__(self, capture_db):
        """
        Takes the database representation object of this capture 
        """
        self.capture_db = capture_db

    
    def init(self, capture: Capture):
        """
        important: called by a freshly created Capture-object cause both that and this object need a reference to each other
        """
        self.capture = capture
    
    def configure(self, options:dict):
        self.options = options

    @abstractmethod
    def process_packet(self, frame):
        """
        This method will be given all raw packets, one at a time.
        Here, all the processing of the packet should take place.
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
        Work that should be done after the last frame has been captured
        AND processed.
        """
        self.capture_db.date_stopped = datetime.utcnow()
        try:
            db.session.add(self.capture_db)
            db.session.commit()
        except Exception as e:
            print(e)


class TestBehavior:
    """
    do not process the packets, just count packets
    """ 
    def start_capture(self):
        self.num_packets = CaptureAttribute(attribute="num_packets", type=AttributeType.Integer)
        self.packet_counter = 0
    
    def process_packet(self, frame):
        self.packet_counter += 1

    def stop_capture(self):
        super().stop_capture()
        self.num_packets.set_value(self.packet_counter)
        self.capture.other_attributes.append(self.num_packets)
        db.session.commit()


class CaptureAllBehavior(CaptureBehavior):
    """
    write all frames into a .pcap
    """

    def __init__(self, cap: FullCapture):
        """
        cap: the database object representing this capture
            Stores all the information needed for this capture behavior
        """
        super().__init__(cap)
        self.channels = cap.get_channels()

        self.gps_tracking = cap.gps_tracking
        self.dir_path = cap.get_dir_path()

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
        super().stop_capture()
        if self.gps_tracking:
            self.gps_route.stop_capture()

    def process_packet(self, frame):
        self.packet_writer.write(frame)
        
#BEGIN OF MapAccessPointsBehavior
class _AccessPoint():
        def __init__(self, bssid, ssid, channel, encryption):
            self.bssid = bssid
            self.ssid = ssid
            self.channel = channel
            self.encryption = encryption
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
    
    def __init__(self, map: Map):
        super().__init__(map)
        #the 802.11 channels to observe 
        self.channels = map.get_channels()

        #bssid as unique identifier, AccessPoint object as value
        # bssid: str -> ap: AcessPoint
        self.aps = dict() #all APs that are uncovered 

        self._running = ThreadEvent() #used to synchronize

        self.map = map

        self.num_aps = 0


    def start_capture(self):
        #also store the number of packets so that we can study the relationship to #discoverered_APs
        self.num_packets = CaptureAttribute(attribute="num_packets", type=AttributeType.Integer)
        self.packet_counter = 0

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


    def process_packet(self, frame):
        self.packet_counter += 1

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

                self.aps[bssid] = ap
                self.num_aps += 1
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
        super().stop_capture()

        #stop threads
        self._running.clear()
        self.hopper.stop_hopping()
        self.cleaning_thread.join()

        #store the number of packets that were processed 
        self.num_packets.set_value(self.packet_counter)
        try:
            self.map.other_attributes.append(self.num_packets)
            db.session.commit()
        except Exception as e:
            print(e)

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
        super().__init__(map)
        #the 802.11 channels to observe 
        self.channels = map.get_channels()
        
        #bssid as unique identifier, AccessPoint object as value
        #bssid: str -> ap: AcessPoint
        self.aps = dict() #all APs that are uncovered 
        self._running = ThreadEvent() #used to synchronize

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


    def process_packet(self, frame):

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

                self.aps[bssid] = ap
                self.num_aps += 1
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

        super().stop_capture()

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
