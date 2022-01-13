import time
import socket
from threading import Thread, Event
from enum import Enum
import json
import logging

from website.settings import ROLE, PORT_SLAVE
import website.interfaces as interfaces
from website.models import Device


#init logger
_logger = logging.getLogger("website.network")


UDP_PORT = PORT_SLAVE
IP_BROADCAST = "255.255.255.255"

class Packet():
    """
    Packet class used for sending messages between sniffers when executing a network discovery.
    """

    #packet types
    class Type():
        """
        Packet types
        """
        REQ_TO_CONNECT = "request to connect"
        CONNECTION_DETAILS = "master reply"
        END = "end"

    def __init__(self, type, body: dict = {}):
        """
        type: the packet type
        body: other information that should be part of this packet encapsulated as a dictionary
        """
        self.content = dict()
        self.content["type"] = type
        self.content.update(body)

    def decode(binary_input):
        """
        Used after receiving a packet from another participant at the lowest level.
        Creates a packet object.

        binary_input: the packet as received in its binary form 
        """
        
        received = json.loads(binary_input.decode('utf-8'))
        p_type = received.get("type")
        return Packet(p_type, received)

    def encode(self):
        """
        Binary representation of this packet which can be sent over a socket.
        """
        return json.dumps(self.content).encode('utf-8')


    def get_type(self) -> str:
        """
        Returns the packet type of this packet.
        """
        return self.content["type"] 
    
    def get(self, packet_field: str):
        """
        Return this field of the packet. If it does not exist, throw an exception.
        """
        field_content = self.content.get(packet_field)
        if field_content is None:
            raise Exception(f"This packet does not have a field '{packet_field}'")
        return field_content
    
    def __repr__(self) -> str:
        return str(self.content)
    

class Participant():
    """
    Encapsulates the information about a sniffer that forms a logical unit with other devices.
    """
    def __init__(self, device_id, ip_address):
       self.ip_address = ip_address 
       self.device_id = device_id
    
    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_device_id(self):
        return self.device_id

    def get_dict(self):
        """
        Return this participant object as a dictionary.
        """
        return {
            'device_id': self.device_id,
            'ip_address': self.ip_address
        }


class Master():

    def __init__(self):
        #dictionary of clients that want to become a slave
        #but that do not know the master's IP address yet
        #structure: {device_identifier: participant_object}
        self.clients_waiting = {} 

        #dicttionary of all fully connected participants
        #structure: {device_identifier: participant_object} 
        self.clients_established = {}

        #Thread used to look for other wsniff devices
        self.discovery_thread = None
        self.discovery_running = Event()

    def get_device(self, device_id: str):
        """
        Searches for a slave with the given device_id and returns its IP address.
        Throws an exception in case there is no participant with this device_id
        """
        for participant in self.get_connected_devices():
            if participant.get_device_id() == device_id:
                return participant
        
        raise Exception(f"There is no participant with device id {device_id}")


    def get_connected_devices(self):
        """
        Returns a list of all participants that are connected to this master node.
        """
        return list(self.clients_established.values())

    def get_pending_devices(self):
        """
        Returns a list of IP addresses of all devices which have requested to connect to a 
        master node but are not allowed yet.
        """
        return self.clients_waiting

    def is_discovery_running(self):
        return self.discovery_running.is_set()

    def discover(self):
        """
        Actually implements the network discovery.
        Executes a handshake between the master and the slave and makes
        sure that each one knows the other's IP address 

        Runs till the corresponding thread is stopped by end_discovery()
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2) 
        sock.bind(("0.0.0.0", UDP_PORT))

        #receive messages till user disables network discovery
        while self.discovery_running.is_set():
            try:
                data, addr = sock.recvfrom(1024)

                packet = Packet.decode(data)
                packet_type = packet.get_type()
                ip_client = addr[0]

                #client wants to connect - but does not know the IP address of the master
                if packet_type == Packet.Type.REQ_TO_CONNECT:
                    #new client
                    #get the device id of this new client
                    device_id = packet.get("device_id")
                    if device_id not in self.clients_waiting:
                        new_participant = Participant(device_id, ip_client)
                        self.clients_waiting[device_id] = new_participant
                        _logger.info(f"[*] %s requested to become a slave.", device_id)

                    #client already made request, but CONNECTION DETAIL reply packet got lost (so he asked again)
                    else:
                        #just resend connection details reply packet
                        pass

                    #send connection details reply to connect with IP of master
                    sock.sendto(Packet(Packet.Type.CONNECTION_DETAILS).encode(), (ip_client, UDP_PORT))


                #ACK that client received connection details packet (including IP address of server)
                #this means both participants can now communicate directly with each other
                elif packet_type == Packet.Type.END:
                    #first time we receive this from the client - we have his information
                    #and now we know he also has our information

                    device_id = packet.get("device_id")
                    if device_id in self.clients_waiting:
                        #move client to list of slaves (with which a conenction has been established)
                        participant = self.clients_waiting.pop(device_id)

                        #this should normally be the case
                        if ip_client not in self.clients_established:
                            self.clients_established[device_id] = participant
                        #the only exception would be a client that executes a network discovery a second time
                        #meaning he is already in the list of participants - then update his IP record since it 
                        #might be that its IP address changed
                        else:
                            self.clients_established[device_id].set_ip_address(participant.get_ip_address())
                            _logger.info("[*] Update IP address of [%s]", device_id)
                        _logger.info("[+] Connection established with [%s]", device_id)
                        print("Current slaves: ")
                        for client in self.clients_established:
                            print(client)

                    #this means we already received one of his END packets in the past
                    #so our END (the ACK of his END packet) got lost
                    #that means we just need to resend it to tell him we got it
                    else:
                        pass

                    sock.sendto(Packet(Packet.Type.END).encode(), (ip_client, UDP_PORT))

                #other packet - should not occur
                else:
                    _logger.warning("[!] Received unknown packet from [%s]: %s", ip_client, str(packet))
            
            except socket.timeout as e:
                pass
        
        #important if user restarts network discovery
        #(prevent address already in use)
        sock.close()


    def start_discovery(self):
        """
        Looks for other devices running wsniff in the same network as a slave and which 
        are currently willing to pair.

        Runs as a seperate thread and should be stopped with end_discovery()
        """
        #if there already is a thread there is no point in running another
        if self.discovery_running.is_set():
            raise Exception("There already is a network discovery running.")

        self.discovery_running.set()
        self.discovery_thread = Thread(target=self.discover, name="network_discovery")
        self.discovery_thread.daemon = True
        self.discovery_thread.start()
        _logger.info("[+] Started network discovery")

    def end_discovery(self):
        """
        Ends the discovery of other wsniff devices.
        """
        if not self.discovery_running.is_set():
            raise Exception("There is no network discovery running.")
        #we use this to determine if there is already a running thread in start_discovery()
        #it is also a trigger to stop a currently running thread
        self.discovery_running.clear()
        #wait for the thread to finish its work
        self.discovery_thread.join()
        _logger.info("[+] Server ended network discovery")


#public access
_master = None
if ROLE == "MASTER":
    _master = Master()

def get_master():
    """
    Get the object encapsulating the information about connected devices.
    """
    if ROLE != "MASTER":
        raise Exception("This device is configured as a slave.")
    return _master


class Slave():

    class State(Enum):
        INIT = 1
        MASTER_KNOWN = 2
        CONNECTION_ESTABLISHED = 3

    def __init__(self):
        self.ip_master = None
        self.state = Slave.State.INIT

        self.device_id = Device.query.first().device_identifier

    def get_master_ip(self):
        return self.ip_master

    def find_master(self):
        """
        Blocks till a master has been found and a connection has been established.
        Stores the IP address of the master
        """
        while self.state != Slave.State.CONNECTION_ESTABLISHED:
            try:
                #here we cannot be sure the master knows us
                #so ensure that
                if self.state == Slave.State.INIT:
                    #try to find master node
                    #create a UDP socket
                    broadcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    #make sure this is sent as a broadcast
                    broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    broadcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                    packet_body = {"device_id": self.device_id}  
                    broadcast_sock.sendto(Packet(Packet.Type.REQ_TO_CONNECT, packet_body).encode(), (IP_BROADCAST, UDP_PORT))
                    broadcast_sock.close()

                    #if you try to use broadcast_sock for receiving that won't work because using SO_BROADCAST=1
                    #to send - so just use a new socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.settimeout(2)
                    sock.bind(("0.0.0.0", UDP_PORT))

                    data, addr = sock.recvfrom(1024)
                    packet = Packet.decode(data)
                    
                    if packet.get_type() == Packet.Type.CONNECTION_DETAILS:
                        #now we know the master's IP address and can switch to the next state
                        self.ip_master = addr[0]
                        _logger.info("[+] Found master: [%s].", self.ip_master)
                        self.state = Slave.State.MASTER_KNOWN
                    else:
                        #remain in the same state
                        _logger.warning("[!] Got some unintended packet: %s", str(packet))
                    sock.close()
                    

                #in this state it is sure the master knows us - and we know the master
                #but we cannot be sure the master knows that we know him
                #so both client and server have to send and receive an END packet
                if self.state == Slave.State.MASTER_KNOWN:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.settimeout(2)
                    sock.bind(("0.0.0.0", UDP_PORT))

                    packet_body = {"device_id": self.device_id}   
                    sock.sendto(Packet(Packet.Type.END, packet_body).encode(), (self.ip_master, UDP_PORT))

                    #now make sure the server received that by waiting for an ACK
                    data, addr = sock.recvfrom(1024)
                    packet = Packet.decode(data)

                    #this means the server has received our END packet and therefore
                    #knows that we are ready
                    if packet.get_type() == Packet.Type.END:
                        self.state = Slave.State.CONNECTION_ESTABLISHED
                        _logger.info("[+] Connection established.")
                        #we could also do a break directly here but I think it is a cleaner implementation of the state machine
                    else:
                        _logger.warning("[!] Got some unintended packet: %s", str(packet))
                    sock.close()

                #network discovery is over - both master and slave have the information they need for communication
                #AND they also know that their counterpart also does
                if self.state == Slave.State.CONNECTION_ESTABLISHED:
                    break

            #in case UDP packet (either one of ours or the server) was lost:
            #we have to repeat this step of the network discovery
            except socket.timeout as e:
                #if broadcast connection request or connection details reply packet are lost, you have to repeat the request
                #logging this does not really make sense
                print("[*] Looking for master ...")
                continue
    
#public access
_slave = None
if ROLE == "SLAVE":
    _slave = Slave()

def get_slave():
    """
    Get the object encapsulating the information about connected devices.
    """
    if ROLE != "SLAVE":
        raise Exception("This device is configured as a master.")
    return _slave    