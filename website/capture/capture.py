from threading import Thread, Event
from time import sleep, time

from website import app
from website.interfaces import Interface
from website.gps import GPSRoute
from website.capture.behavior import CaptureBehavior

from scapy.all import *

"""
here all important infos of a capture are encapsulated
"""
class Capture:

    """
    interface: interface object -> this interface will be used for the capturing process
    capture_behavior: this behavior object determines what will happen during a capture (implemented using the strategy pattern)
    """
    def __init__(self, id: int, interface: Interface, capture_behavior: CaptureBehavior):
        self.id = id
        self.interface = interface
        self.capture_behavior = capture_behavior
        capture_behavior.init(self) #important: capture behavior needs a reference to its capture

        self.dirpath = os.path.join(app.root_path, "static", "captures", str(id))
        print(self.dirpath)
        self.num_packets = 0
        self._stop = Event()

    def _handle_packet(self, pkt):
        #call hook
        self.capture_behavior.handle_packet(pkt)
        
    """
    method called by capture/sniffing thread: used to actually capture WIFI-frames
    """
    def _capture(self):
        #TODO: using scapy create file and scan till stop event is set, 
        #you could create a class to update information such as packet count, beacons, ...
        #use locks
        #entweder Capture von Thread erben oder thread kapseln (vielleicht bessere idee)
        while True:
            if self._stop.is_set():
                break
            sniff(iface=self.interface.get_name(), prn=self._handle_packet, count=5, timeout=2)

    def start(self):
        #call hook
        self.capture_behavior.start_capture()

        #create sniffing/capture thread
        self.t = Thread(target=self._capture, name="capture_"+str(self.id))
        self.t.daemon = True
        self.t.start()        

        print(f"[+] Capture {self.id} Started")
    
    def stop(self):
        #stop capturing of frames
        self._stop.set()
        self.t.join()
        
        #call hook
        self.capture_behavior.stop_capture()

        print(f"[+] Capture {self.id} Stopped")

    def get_num_packets(self):
        return self.num_packets

#END OF CLASS Capture


captures = dict()
"""
this function is supposed to be called from outside to start a capture
interface: interface object -> this interface will be used for the capturing process
capture_behavior: this behavior object determines what will happen during a capture (implemented using the strategy pattern)
"""
def start_capture(id: int, interface: Interface, capture_behavior: CaptureBehavior):
    if captures.get(id):
        raise ValueError(f"Capture '{id}' already running.")
    
    #add capture
    c = Capture(id, interface, capture_behavior)
    captures[id] = c
    c.start()

"""
you can call this function from outside if you want to stop a running capture with the given id
id: ID of the running capture to be stopped
"""  
def stop_capture(id):
    try: 
        c = captures.pop(id)
        c.stop()
    except:
        raise ValueError(f"Capture '{id}' can't be stopped since it does not exist.")

"""
returns the Capture-object with this id, can be called from outside
"""
def get_capture(id):
    c = captures.get(id)
    if not c:
        raise ValueError(f"Capture {id} does not exist.")
    return c
    
"""
can be called from outside to get a list of all the running captures
"""
def get_running_ids():
    return list(captures.keys())
    
    
