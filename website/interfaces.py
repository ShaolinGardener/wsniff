import sys
from enum import Enum
import subprocess
#using this instead of directly list[...] since there is only Python 3.7 on a RPi by default
from typing import List


class Mode(Enum):
        MANAGED = 1
        MONITOR = 2

class Interface:
    """
    For each WLAN/Wi-Fi adapter a user connects to the raspberry, a new instance of this
    class is created. It offers some helpful methods to access the hardware.
    """

    def __init__(self, name: str, mode:Mode = Mode.MANAGED):
        self.mode = mode

        if mode == Mode.MONITOR:
            #assuming it follows this pattern of ending monitoring interfaces with 'mon'
            self.name = name[:-3]
            self.mon_name = name
            self.current_name = name
        else:
            self.name = name
            self.mon_name = name + "mon"
            self.current_name = name

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
        Enables monitor mode of interface.
        raises subprocess.CalledProcessError error in case some error occurs
        """
        subprocess.run(self.str_monitor_enable, shell=True, check=True)
        self.mode = Mode.MONITOR
        self.current_name = self.mon_name
        print(f"[+] Activated monitor mode for {self.name}")

    def disable_monitor_mode(self):
        """
        Returns this interface to managed mode.
        raises subprocess.CalledProcessError error in case some error occurs
        """

        subprocess.run(self.str_monitor_disable, shell=True, check=True)
        self.mode = Mode.MANAGED
        self.current_name = self.name
        print(f"[+] Deactivated monitor mode for {self.name}")

    def set_channel(self, channel: int):
        """
        Sets the channel of this interface to the given value.
        raises subprocess.CalledProcessError error in case some error occurs
        """
        subprocess.run(f"iwconfig {self.current_name} channel {channel}", shell=True, check=True)


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



def monitor_interface_available():
    """
    Returns if there is at least one interface in monitor mode connected to the raspberry.
    """
    #wireless interfaces
    iw = _get_wireless_interface_names()
    #get wireless interfaces in monitor mode
    mon_iw = list(filter(lambda iface: "mon" in iface, iw))
    return len(mon_iw) > 0



#a dict of all interfaces available
interfaces = {}
#initialize it in case there are already some interfaces in monitor mode when starting wsniff
names = _get_wireless_interface_names()
for name in names:
    if "mon" in name:
        interfaces[name[:-3]] = Interface(name, Mode.MONITOR)
    else:
        interfaces[name] = Interface(name, Mode.MANAGED)

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



