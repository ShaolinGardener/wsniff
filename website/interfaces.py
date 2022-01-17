import sys
from enum import Enum
import subprocess
import logging
#using this instead of directly list[...] since there is only Python 3.7 on a RPi by default
from typing import List

#init logger
_logger = logging.getLogger("website.interfaces")

class Mode(Enum):
        MANAGED = 1
        MONITOR = 2

class Interface:
    """
    For each WLAN/Wi-Fi adapter a user connects to the raspberry, a new instance of this
    class is created. It offers some helpful methods to access the hardware.
    """

    def __init__(self, name: str, mode:Mode = Mode.MANAGED):
        """
        name: the actual name the interface currently has
        """
        self.mode = mode

        self.real_name = name
        if mode == Mode.MONITOR:
            #assuming it follows this pattern of ending monitoring interfaces with 'mon'
            if "mon" in name:
                #name is basically the "managed_name"
                self.name = name[:-3]
                self.mon_name = name
            else:
                self.name = name
                self.mon_name = name + "mon"
        else:
            self.name = name
            self.mon_name = name + "mon"

        #the 802.11 channels that this interface can listen on
        self.channels = self.get_channels()

        self.str_monitor_enable  = f"ifconfig {self.name} down; iw dev {self.name} interface add {self.mon_name} type monitor; ifconfig {self.mon_name} down; iw dev {self.mon_name} set type monitor; ifconfig {self.mon_name} up"
        self.str_monitor_disable = f"iw dev {self.mon_name} del; ifconfig {self.name} up"
        self.str_monitor_enable_new  = f"sudo ip link set {self.name} down; sudo iw dev {self.name} interface add {self.mon_name} type monitor; sudo ip link set {self.mon_name} down; sudo iw dev {self.mon_name} set type monitor; sudo ip link set {self.mon_name} up"
        self.str_monitor_disable_new = f"sudo iw dev {self.mon_name} del; sudo ip link set {self.name} up"

        self.str_monitor_enable_new  = f"sudo ip link set {self.name} down; \
                                        sudo iw dev {self.name} interface add {self.mon_name} type monitor; \
                                        sudo ip link set {self.mon_name} down; \
                                        sudo iw dev {self.mon_name} set type monitor; \
                                        sudo ip link set {self.mon_name} up" 
        self.str_monitor_disable_new = f"sudo iw dev {self.mon_name} del; \
                                        sudo ip link set {self.name} up"


    def __str__(self):
        return f"{self.name}"

    def get_name(self):
        """
        Return the monitor name if the adapter is in monitor mode,
        otherwise the name it has in its managed mode
        """
        return self.real_name
        #old
        if self.mode == Mode.MONITOR:
            return self.mon_name
        else:
            return self.name

    def get_managed_name(self):
        return self.name

    def get_monitor_name(self):
        return self.mon_name

    def enable_monitor_mode(self):
        """
        Enables monitor mode of interface.
        raises subprocess.CalledProcessError error in case some error occurs
        """
        subprocess.run(self.str_monitor_enable, shell=True, check=True)
        self.mode = Mode.MONITOR
        self.real_name = self.mon_name
        _logger.info("[+] Activated monitor mode for %s", self.name)

    def disable_monitor_mode(self):
        """
        Returns this interface to managed mode.
        raises subprocess.CalledProcessError error in case some error occurs
        """

        subprocess.run(self.str_monitor_disable, shell=True, check=True)
        self.mode = Mode.MANAGED
        self.real_name = self.name
        _logger.info("[+] Deactivated monitor mode for %s", self.name)
 
    def get_channels(self):
        interface = self.real_name
        channels = []
        try:
            cmd = f"iwlist {interface} channel"
            proc_res = subprocess.run(cmd, capture_output=True, shell=True, check=True)
            res = proc_res.stdout.decode('utf-8')
            channels = list(map(lambda line: int(line.split(' ')[-4]), res.split('\n')[1:-3]))
        except subprocess.CalledProcessError as e:
            _logger.exception(f'[-] Could not determine available channels for interface %s', interface)
        return channels 
    
    def get_channel_string(self):
        """
        Returns the supported channels as a string
        """
        return ', '.join(map(lambda ch: str(ch), self.channels))

    def set_channel(self, channel: int):
        """
        Sets the channel of this interface to the given value.
        raises subprocess.CalledProcessError error in case some error occurs
        """
        subprocess.run(f"iwconfig {self.real_name} channel {channel}", shell=True, check=True)


def _get_interface_names():
    """
    Get the names of all interfaces that are currently plugged in the raspberry
    Returns: a list of all interfaces as strings
    """
    if sys.platform.startswith('linux'):
        #here infos about available network interfaces are stored (along their name)
        f = open("/proc/net/dev", "r")
        #discard first two and last line + we only need the first column of the file
        return list(map(lambda line: line.split(":")[0].strip(), f.read().split("\n")[2:]))[:-1]
    else:
        #other OS are not supported yet
        return []

def _get_wireless_interface_names():
    """
    Only get wireless interfaces that are currently plugged in as a list of strings.
    """
    ifaces = _get_interface_names()
    return list(filter(lambda iface: "wlan" in iface, ifaces))


#a dict of all interfaces available
interfaces = {}
#initialize it in case there are already some interfaces in monitor mode when starting wsniff
#especially the ones you have to manually put in monitor mode (because their driver sucks)
cmd = "iwconfig"
proc_res = subprocess.run(cmd, text=True, capture_output=True, shell=True, check=True)
output = proc_res.stdout
lines = output.split("\n")
for i, line in enumerate(lines):
    if line.startswith("wlan"):
        interface_name = line.split(" ")[0]
        if "Monitor" in line or "Monitor" in lines[i+1]:
            interfaces[interface_name] = Interface(interface_name, Mode.MONITOR)
        else:
            interfaces[interface_name] = Interface(interface_name, Mode.MANAGED)


def monitor_interface_available():
    """
    Returns if there is at least one interface in monitor mode connected to the raspberry.
    """
    for interface in interfaces.values():
        if interface.mode == Mode.MONITOR:
            return True
    return False

def update_interfaces():
    """
    Check for unplugged/newly plugged WLAN interfaces
    Returns: for convenience, directly return updated dict of interfaces
    """
    #wireless interfaces
    iw = _get_wireless_interface_names()
    #this list represents all existing cards
    actual_cards = set(filter(lambda iface: "mon" not in iface, iw))
    old_cards = set(interfaces.keys())

    #compute which interfaces were added and which ones were removed since the last update
    add = actual_cards.difference(old_cards)
    remove = old_cards.difference(actual_cards)

    #do the actual update
    for interface in add:
        interfaces[interface] = Interface(interface)
    for interface in remove:
        interfaces.pop(interface)

    return interfaces


def get_all_interfaces():
    """
    Get a list of all interfaces
    """
    return update_interfaces()

def get_interfaces(mode: Mode) -> List[Interface]:
    """
    Returns a list of interface objects which are in the specified mode
    """
    update_interfaces()
    res = []
    for iface in interfaces:
        if interfaces[iface].mode == mode:
            res.append(interfaces[iface])
    return res



