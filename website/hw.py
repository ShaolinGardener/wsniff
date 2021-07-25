from threading import Thread, Event
from time import sleep, time

from website import app
from website.interfaces import monitor_iface
from website.gps import GPSRoute

from scapy.all import *

class _Capture:

    def __init__(self, id: int, channel: int, interface: str, gps_tracking: bool):
        self.id = id
        self.channel = channel
        self.interface = interface
        
        if gps_tracking: #TODO: name of route using db to query for capture title maybe?
            path = os.path.join(app.root_path, "static", "captures", str(id), "gps.txt")
            self.gps_route = GPSRoute(str(id), path)

        path = os.path.join(app.root_path, "static", "captures", str(id), "cap.pcap")
        self.packet_writer = PcapWriter(path,
                                        append=True, sync=True)
        
        self.num_packets = 0

        self._stop = Event()

    def _handle_packet(self, pkt):
        # if not pkt.haslayer(Dot11):
        #     return
        # source = pkt.getlayer(Dot11).addr1
        # source = pkt.getlayer(Dot11).addr4
        
        self.num_packets += 1
        self.packet_writer.write(pkt)

    def _capture(self):
        #TODO: using scapy create file and scan till stop event is set, 
        #you could create a class to update information such as packet count, beacons, ...
        #use locks
        #entweder Capture von Thread erben oder thread kapseln (vielleicht bessere idee)
        monitor_iface.set_channel(self.channel)

        while True:
            if self._stop.is_set():
                break
            sniff(iface=self.interface, prn=self._handle_packet, count=5, timeout=2)

    def start(self):
        self.t = Thread(target=self._capture)
        self.t.start()

        if self.gps_route:
            self.gps_route.start_capture()

        print(f"[+] Capture {self.id} Started")
    
    def stop(self):
        self._stop.set()
        self.t.join()

        if self.gps_route:
            self.gps_route.stop_capture()

        print(f"[+] Capture {self.id} Stopped")

    
    def get_num_packets(self):
        return self.num_packets


#TODO: use redis for multiple captures using many WIFI-Adapters
captures = dict()
def start_capture(id: int, channel: int, interface: str, gps_tracking: bool):
    if captures.get(id):
        raise ValueError(f"Capture '{id}' already running.")
    #add capture
    c = _Capture(id, channel, interface, gps_tracking)
    captures[id] = c
    c.start()

    
def stop_capture(id):
    try: 
        c = captures.pop(id)
        c.stop()
    except:
        raise ValueError(f"Capture '{id}' can't be stopped since it does not exist.")

def get_capture(id):
    c = captures.get(id)
    if not c:
        raise ValueError(f"Capture {id} does not exist.")
    return c
    
def get_running_ids():
    return list(captures.keys())

def callback(frame):
    print(frame)


def test_capture():
    start_capture("blub", 11, interface="wlan0mon")
    start_capture("2", 2, interface="wlan0mon")
    stop_capture("blub")
    stop_capture("2")

def test_interface():
    iface = Interface("wlan1")
    iface.enable_monitor_mode()
    iface.set_channel(7)

if __name__ == "__main__":
    test_interface()
    
