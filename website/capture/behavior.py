from abc import ABC, abstractmethod
from threading import Thread, Event
from time import sleep, time

from website import app
from website.interfaces import Interface
from website.gps import GPSRoute

from scapy.all import *


"""
abstract base class for defining the capturing behavior of a capture
"""
class CaptureBehavior(ABC):

    """
    important: called by a freshly created Capture-object cause both that and this object need a reference to each other
    """
    def init(self, capture):
        self.capture = capture

    @abstractmethod
    def handle_packet(self, frame):
        pass

    #hook methods
    """
    called before first frame is captured
    """
    def start_capture(self):
        pass

    """
    called after last frame has been captured
    """
    def stop_capture(self):
        pass

"""
do not capture any packets
"""
class TestBehavior:
    
    def handle_packet(self, frame):
        pass

"""
write all frames into a .pcap
"""
class CaptureAllBehavior(CaptureBehavior):

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
            self.gps_route = GPSRoute(str(id), path)

        #do this in the end (that's why we use an additional if-clause since there could be isnerted new code above later on)
        if self.gps_tracking:
            self.gps_route.start_capture()

    def stop_capture(self):
        if self.gps_tracking:
            self.gps_route.stop_capture()

    def handle_packet(self, frame):
        self.packet_writer.write(frame)
        self.capture.num_packets += 1
        
"""
can be used to create a map of access points / wardriving
"""
class MapAccessPointsBehavior(CaptureBehavior):
    
    def __init__(self):
        self.filepath = os.join(self.capture.dirpath, "wardrive.txt")
       
        #bssid as unique identifier, AccessPoint object as value
        # bssid: str -> ap: AcessPoint
        self.aps = dict() #all APs that are uncovered 
        self._running = Event() #used to synchronize

    class AccessPoint():
        def __init__(self, bssid, ssid, channel):
            self.bssid = bssid
            self.ssid = ssid
            self.channel = channel
            self.signal_strength = 0
            #gps coordinates
            self.lat, self.lon = gps.get_gps_data()

            self.t_last_seen = time.time()
        
        def isAlive(self, t_death=20):
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

    def start_capture(self):
        #hop through channels - hoppin thread
        self._running.set()
        interface = self.capture.interface
        hopping_thread = Thread(target=self.hopper, args=(interface, ), name="hopper")
        self.hopping_thread = hopping_thread #we need a reference to stop thread later on
        hopping_thread.daemon = True
        hopping_thread.start()

    def hopper(self, iface):
        channel = 1
        stop_hopper = False
        while _running.is_set():
            sleep(0.25)
            os.system(f"sudo iwconfig {iface} channel {channel}")
            #print(f"[*] current channel {channel}")
            
            dig = int(random.random() * 13) + 1
            if dig != channel:
                channel = dig

    def handle_packet(self, capture, frame): 
        self.capture.num_packets += 1

        if frame.haslayer(Dot11Beacon):
            #bssid of AP is stored in second address field of header
            bssid = frame.getlayer(Dot11).addr2 

            #found new access point: add it to dict
            if bssid not in self.aps:
                ssid = frame.getlayer(Dot11Elt).info.decode("utf-8")
                channel = frame.getlayer(Dot11Elt).channel
                ap = AccessPoint(bssid, ssid, channel)

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

        #store in file   
        f = open(self.filepath, "w") 
        for bssid in self.aps:
            #better to read here than f"-Syntax
            ap = self.aps[bssid]
            f.write("{time};{bssid};{ssid};{channel};{vendor};{lat};{lon}\n".format(time=ap.t_last_seen, bssid=ap.bssid, ssid=ap.ssid, channel=ap.channel, vendor=oui.lookup(ap.bssid), lat=ap.lat, lon = ap.lon))
        f.close()
        self.aps.clear()

#END OF CAPTURE BAHAVIOR CLASSES

