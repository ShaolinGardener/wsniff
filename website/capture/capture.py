from threading import Thread, Event
import os
#using this instead of list[...] since there is only Python 3.7 on a RPi by default
from typing import List

from website import app
from website.interfaces import Interface
from website.capture.behavior import CaptureBehavior

from scapy.all import *


class Capture:
    """
    here all important infos of a capture are encapsulated
    """

    def __init__(self, id: int, interfaces: List[Interface], capture_behavior: CaptureBehavior):
        """
        interface: interface object -> this interface will be used for the capturing process
        capture_behavior: this behavior object determines what will happen during a capture (implemented using the strategy pattern)
        """
        self.id = id
        self.interfaces = interfaces
        self.capture_behavior = capture_behavior
        capture_behavior.init(self) #important: capture behavior needs a reference to its capture

        self.num_packets = 0
        self._stop = Event()

    def _handle_packet(self, pkt):
        """
        Called every time a new packet has been sniffed.
        The processing of the packet depends on the capture behavior.
        """
        #call hook
        self.capture_behavior.handle_packet(pkt)


    def _capture(self, interface:Interface):
        """
        method called by capture/sniffing thread: used to actually capture WIFI-frames
        """
        #TODO: using scapy create file and scan till stop event is set,
        #you could create a class to update information such as packet count, beacons, ...
        #use locks
        #entweder Capture von Thread erben oder thread kapseln (vielleicht bessere idee)
        iface_name = interface.get_name()
        while True:
            if self._stop.is_set():
                break
            sniff(iface=iface_name, prn=self._handle_packet, count=5, timeout=2)

    def start(self):
        #call hook
        self.capture_behavior.start_capture()

        #create sniffing/capture threads
        self.capture_threads = []
        for interface in self.interfaces:
            t = Thread(target=self._capture, args=(interface,), name="capture_"+str(self.id))
            t.daemon = True
            t.start()
            self.capture_threads.append(t)
            print("[*] Started capture thread.")

        print(f"[+] Capture {self.id} Started")

    def stop(self):
        #stop capturing of frames
        self._stop.set()
        for thread in self.capture_threads:
            thread.join()
            print("[*] Stopped capture thread.")

        #call hook
        self.capture_behavior.stop_capture()

        print(f"[+] Capture {self.id} Stopped")

    def get_num_packets(self):
        return self.num_packets

#END OF CLASS Capture


captures = dict()

def start_capture(id: int, interfaces: List[Interface], capture_behavior: CaptureBehavior):
    """
    this function is supposed to be called from outside to start a capture
    interface: interface object -> this interface will be used for the capturing process
    capture_behavior: this behavior object determines what will happen during a capture (implemented using the strategy pattern)
    """
    if captures.get(id):
        raise ValueError(f"Capture '{id}' already running.")

    #add capture
    c = Capture(id, interfaces, capture_behavior)
    captures[id] = c
    c.start()


def stop_capture(id):
    """
    you can call this function from outside if you want to stop a running capture with the given id
    id: ID of the running capture to be stopped
    """
    try:
        c = captures.pop(id)

        c.stop()
    except:
        raise ValueError(f"Capture '{id}' can't be stopped since it does not exist.")


def get_capture(id):
    """
    returns the Capture-object with this id, can be called from outside
    """
    c = captures.get(id)
    if not c:
        raise ValueError(f"Capture {id} does not exist.")
    return c


def get_running_ids():
    """
    can be called from outside to get a list of all the running captures
    """
    return list(captures.keys())


