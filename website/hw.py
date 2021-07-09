from threading import Thread, Event
from time import sleep, time

from scapy.all import *




class _Capture:
    def __init__(self, id: int, channel: int, interface: str):
        self.id = id
        self.channel = channel
        self.interface = interface
        
        self.num_packets = 0

        self._stop = Event()

    def _handle_packet(self, pkt):
        self.num_packets += 1

    def _capture(self):
        #TODO: using scapy create file and scan till stop event is set, 
        #you could create a class to update information such as packet count, beacons, ...
        #use locks
        #entweder Capture von Thread erben oder thread kapseln (vielleicht bessere idee)
        
        while True:
            if self._stop.is_set():
                break
            sniff(iface="en0", prn=self._handle_packet, count=5, timeout=2)

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


def main():
    stop_capture("blub")
    start_capture("blub", 11)
    start_capture("blub", 11)
    start_capture("2", 2)
    stop_capture("blub")
    stop_capture("2")

def callback(frame):
    print(frame)

if __name__ == "__main__":
    main()
    
