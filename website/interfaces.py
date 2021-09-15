import sys
from enum import Enum
import subprocess


class Mode(Enum):
        MANAGED = 1
        MONITOR = 2

class Interface:

    def __init__(self, name: str, mode:Mode = Mode.MANAGED):
        self.mode = mode

        if mode == Mode.MONITOR:
            #assuming it follows this pattern of ending monitoring interfaces with 'mon'
            self.name = name[:-3] 
            self.mon_name = name
        else:
            self.name = name
            self.mon_name = name + "mon"

        self.str_monitor_enable  = f"ifconfig {self.name} down; iw dev {self.name} interface add {self.mon_name} type monitor; ifconfig {self.mon_name} down; iw dev {self.mon_name} set type monitor; ifconfig {self.mon_name} up"
        self.str_monitor_disable = f"iw dev {self.mon_name} del; ifconfig {self.name} up"
        

    def __str__(self):
        return f"{self.name}"

    def get_name(self):
        if self.mode == Mode.MONITOR:
            return self.mon_name
        else:
            return self.name

    def enable_monitor_mode(self):
        """
        raises subprocess.CalledProcessError error in case some error occurs
        """
        subprocess.run(self.str_monitor_enable, shell=True, check=True)
        self.mode = Mode.MONITOR
        print(f"[+] Activated monitor mode for {self.name}")

    def disable_monitor_mode(self):
        """
        raises subprocess.CalledProcessError error in case some error occurs
        """
        
        subprocess.run(self.str_monitor_disable, shell=True, check=True)
        self.mode = Mode.MANAGED
        print(f"[+] Deactivated monitor mode for {self.name}")

    def set_channel(self, channel: int):
        """
        raises subprocess.CalledProcessError error in case some error occurs
        """
        if self.mode == Mode.MONITOR:
            n = self.mon_name
        else:
            n = self.name
        subprocess.run(f"iwconfig {n} channel {channel}", shell=True, check=True)


def _get_interface_names():
    """
    Returns: a list of all interfaces
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
    Only get wireless interfaces
    """
    ifaces = _get_interface_names()
    return list(filter(lambda iface: "wlan" in iface, ifaces))



def monitor_interface_available():
    #wireless interfaces
    iw = _get_wireless_interface_names() 
    #get wireless interfaces in monitor mode
    mon_iw = list(filter(lambda iface: "mon" in iface, iw))
    return len(mon_iw) > 0



#a dict of all interfaces available
interfaces = {}

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

def get_interfaces(mode: Mode):
    """
    Returns a list of interface objects which are in the specified mode
    """
    update_interfaces()
    res = []
    for iface in interfaces:
        if interfaces[iface].mode == mode:
            res.append(interfaces[iface])
    return res



