from multiprocessing import Process, Event as ProcessEvent, Value, JoinableQueue
#using this instead of list[...] since there is only Python 3.7 on a RPi by default
from typing import List
import queue

from website import app
from website.interfaces import Interface
from website.capture.behavior import CaptureBehavior

from scapy.all import *


class Capture:
    """
    here all important infos of a capture are encapsulated
    """

    class PoisonPill():
        """
        Class which is needed for synchronization. Insert an instance of this class to a queue to 
        inform the consumers of the queue that they can stop their work.
        """
        pass

    def __init__(self, id: int, interfaces: List[Interface], capture_behavior: CaptureBehavior):
        """
        interface: interface object -> this interface will be used for the capturing process
        capture_behavior: this behavior object determines what will happen during a capture (implemented using the strategy pattern)
        """
        self.id = id
        self.interfaces = interfaces
        self.capture_behavior = capture_behavior
        capture_behavior.init(self) #important: capture behavior needs a reference to its capture

        #when a client wants to stop the capture, this event is set
        self._stop = ProcessEvent()
        #we cannot directly stop processing after the stop event has been set. A consumer process
        #will have to wait till he retrieves a poison pill object out of his queue
        self.poison_pill = Capture.PoisonPill()
        #this is the interface between sniffing processes which actually sniff packets and the 
        #consuming ones who are concerned with processing the packets
        self.packet_buffer = JoinableQueue()
        #this value might be shared between multiple processes, so make it thread/process-safe
        self.num_packets = Value('L', 0)

    def _sniff_packet(self, packet_buffer:JoinableQueue):
        """
        Called every time a new packet has been sniffed.
        The processing of the packet depends on the capture behavior.
        """

        # store_packet function has access to the queue since it is nested within
        def store_packet(packet):
            # store packet in buffer where it can be retrieved by a consumer process
            try:
                packet_buffer.put(packet, block=False)
            except queue.Full as e:
                print(f"[-] Error processing packet: Queue full \n{e}")
        
        #since scapy expects a callback function with exactly one parameter, we need to return store_packet
        #and can not just use _handle_packet (this is why we have to make use of a nested function)
        return store_packet
        

    def _capture(self, interface:Interface, packet_buffer:JoinableQueue):
        """
        method called by capture/sniffing thread: used to actually capture WIFI-frames
        """
        iface_name = interface.get_name()
        while True:
            if self._stop.is_set():
                break
            sniff(iface=iface_name, prn=self._sniff_packet(packet_buffer), count=5, timeout=2)
            
            #+= operation means there is a hidden read-write race condition, so we need to lock this
            with self.num_packets.get_lock():
                #increasing this here instead of simply incrementing it in _handle_packet might 
                #introduce a total inaccuracy of 5 packets, but there is less synchronization effort
                #required, basically increasing performance
                self.num_packets.value += 5


    def _process_packet(self, packet_buffer:JoinableQueue):
        while True:
            #we can create an infinite loop with a blocking operation here since we can be sure 
            #that at one point in time we will receive a poison pill object
            packet = packet_buffer.get(block=True)
            if isinstance(packet, Capture.PoisonPill):
                #this process can now savely end its work (there will be no new packets)
                break
            
            #if this is a real packet
            #call hook
            self.capture_behavior.process_packet(packet)

        #now we can be sure that there are no further packets,
        #so we can call the stop capture hook
        #note: it is important to call it from within this function
        #(which is also the one processing the packets within THE SAME PROCESS)
        #to guarantee visibility 
        self.capture_behavior.stop_capture()

    def start(self):
        #call hook
        self.capture_behavior.start_capture()

        #all processes that are part of this capture
        self.capture_processes = []

        #create process that processes packets
        packet_processor = Process(target=self._process_packet, args=(self.packet_buffer, ), name=f"capture_{self.id}_processor")
        packet_processor.daemon = True
        packet_processor.start()
        self.capture_processes.append(packet_processor) 

        #create sniffing processes
        for interface in self.interfaces:
            t = Process(target=self._capture, args=(interface, self.packet_buffer), name=f"capture_{self.id}_sniffer")
            t.daemon = True
            t.start()
            self.capture_processes.append(t)
            print("[*] Started capture process.")


        print(f"[+] Capture {self.id} Started")

    def stop(self):
        #stop capturing of frames
        self._stop.set()
        self.packet_buffer.put(self.poison_pill)

        for process in self.capture_processes:
            process.join()
            print("[*] Stopped capture process.")


        print(f"[+] Capture {self.id} Stopped")

    def get_num_packets(self):
        return self.num_packets.value

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


