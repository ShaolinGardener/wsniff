from threading import Thread, Event
from time import sleep, time
import subprocess

from website import app

from scapy.all import *



class Interface:
      
    def __init__(self, name: str):
        self.name = name
        self.mon_name = name + "mon"
        self.str_monitor_enable  = f"ifconfig {self.name} down; iw dev {self.name} interface add {self.mon_name} type monitor; ifconfig {self.mon_name} down; iw dev {self.mon_name} set type monitor; ifconfig {self.mon_name} up"
        self.str_monitor_disable = f"iw dev {self.mon_name} del; ifconfig {self.name} up"
    
    def enable_monitor_mode(self):
        subprocess.run(self.str_monitor_enable, shell=True, check=True)

    def disable_monitor_mode(self):
        subprocess.run(self.str_monitor_disable, shell=True, check=True)

    def set_channel(self, channel: int):
        subprocess.run(f"sudo iwconfig {self.name} channel {channel}")

class _Capture:
    def __init__(self, id: int, channel: int, interface: str):
        self.id = id
        self.channel = channel
        self.interface = interface

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
        
        while True:
            if self._stop.is_set():
                break
            sniff(iface=self.interface, prn=self._handle_packet, count=5, timeout=2)

    def start(self):
        self.t = Thread(target=self._capture)
        self.t.start()
        print(f"[+] Capture {self.id} Started")
    
    def stop(self):
        self._stop.set()
        self.t.join()
        print(f"[+] Capture {self.id} Stopped")

    
    def get_num_packets(self):
        return self.num_packets


#TODO: use redis for multiple captures using many WIFI-Adapters
captures = dict()
def start_capture(id: int, channel: int, interface: str):
    if captures.get(id):
        raise ValueError(f"Capture '{id}' already running.")
    #add capture
    c = _Capture(id, channel, interface)
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

if __name__ == "__main__":
    test_interface()
    
