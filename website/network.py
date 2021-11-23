import time
import socket
from threading import Thread, Event
from enum import Enum

from website.settings import ROLE

UDP_PORT = 4242
IP_BROADCAST = "255.255.255.255"

#packets
REQ_TO_CONNECT = "request to connect"
CONNECTION_DETAILS = "master reply"
END = "end"

class Master():
    def __init__(self):
        #IP addresses of clients that want to become a slave
        #but that do not know the master's IP address yet
        self.clients_waiting = []

        #IP adresses of all fully connected clients
        self.clients_established = []

        #Thread used to look for other wsniff devices
        self.discovery_thread = None
        self.discovery_running = Event()

    def get_connected_devices(self):
        """
        Returns a list of IP addresses of all devices that are connected to this master node.
        """
        return self.clients_established

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
                msg = data.decode("utf-8")
                ip_client = addr[0]

                #client wants to connect - but does not know the IP address of the master
                if msg == REQ_TO_CONNECT:
                    #new client
                    if ip_client not in self.clients_waiting:
                        self.clients_waiting.append(ip_client)
                        print(f"[*] {ip_client} requested to become a slave.")

                    #client already made request, but CONNECTION DETAIL reply packet got lost (so he asked again)
                    else:
                        #just resend connection details reply packet
                        pass

                    #send connection detials reply to connect with IP of master
                    sock.sendto(str.encode(CONNECTION_DETAILS), (ip_client, UDP_PORT))


                #ACK that client received connection details packet (including IP address of server)
                #this means both participants can now communicate directly with each other
                elif msg == END:
                    #first time we receive this from the client - we have his information
                    #and now we know he also has our information
                    if ip_client in self.clients_waiting:
                        #move client to list of slaves (with which a conenction has been established)
                        self.clients_waiting.remove(ip_client)

                        #this should normally be the case
                        if ip_client not in self.clients_established:
                            self.clients_established.append(ip_client)
                        #the only exception would be a client that executes a network discovery a second time
                        #meaning he is already in the list of slaves - then prevent duplicates
                        else:
                            pass
                        print(f"[+] Connection established with [{ip_client}]")
                        for client in self.clients_established:
                            print(client)

                    #this means we already received one of his END packets in the past
                    #so our END (the ACK of his END packet) got lost
                    #that means we just need to resend it to tell him we got it
                    else:
                        pass

                    sock.sendto(str.encode(END, "utf-8"), (ip_client, UDP_PORT))

                #other msg - should not occur
                else:
                    print(f"[!] Received message from [{ip_client}]: {msg}")
            
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
        print("[+] Started network discovery")

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
        print("[+] Server ended network discovery")


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


class Slave(Thread):

    class State(Enum):
        INIT = 1
        MASTER_KNOWN = 2
        CONNECTION_ESTABLISHED = 3

    def __init__(self):
        self.ip_master = None
        self.state = Slave.State.INIT

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

                    broadcast_sock.sendto(str.encode(REQ_TO_CONNECT, "utf-8"), (IP_BROADCAST, UDP_PORT))
                    broadcast_sock.close()

                    #if you try to use broadcast_sock for receiving that won't work because using SO_BROADCAST=1
                    #to send - so just use a new socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.settimeout(2)
                    sock.bind(("0.0.0.0", UDP_PORT))

                    data, addr = sock.recvfrom(1024)
                    msg = data.decode("utf-8")
                    
                    if msg == CONNECTION_DETAILS:
                        #now we know the master's IP address and can switch to the next state
                        self.ip_master = addr[0]
                        print(f"[+] Found master: [{self.ip_master}].")
                        self.state = Slave.State.MASTER_KNOWN
                    else:
                        #remain in the same state
                        print(f"[!] Got some unintended message: {msg}")
                    sock.close()
                    

                #in this state it is sure the master knows us - and we know the master
                #but we cannot be sure the master knows that we know him
                #so both client and server have to send and receive an END packet
                if self.state == Slave.State.MASTER_KNOWN:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.settimeout(2)
                    sock.bind(("0.0.0.0", UDP_PORT))

                    sock.sendto(str.encode(END), (self.ip_master, UDP_PORT))

                    #now make sure the server received that by waiting for an ACK
                    data, addr = sock.recvfrom(1024)
                    msg = data.decode("utf-8")

                    #this means the server has received our END packet and therefore
                    #knows that we are ready
                    if msg == END:
                        self.state = Slave.State.CONNECTION_ESTABLISHED
                        print(f"[+] Connection established.")
                        #we could also do a break directly here but I think it is a cleaner implementation of the state machine
                    else:
                        print(f"[!] Got some unintended message: {msg}")
                    sock.close()

                #network discovery is over - both master and slave have the information they need for communication
                #AND they also know that their counterpart also does
                if self.state == Slave.State.CONNECTION_ESTABLISHED:
                    break

            #in case UDP packet (either one of ours or the server) was lost:
            #we have to repeat this step of the network discovery
            except socket.timeout as e:
                #if broadcast connection request or connection details reply packet are lost, you have to repeat the request
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