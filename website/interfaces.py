from website.settings import INTERFACE

from enum import Enum
import subprocess

def get_interfaces():
    """
    Returns: a list of all interfaces
    """
    f = open("/proc/net/dev", "r") #here infos about available network interfaces are stored (along their name)
    #discard first two and last line + we only need the first column of the file
    return list(map(lambda line: line.split(":")[0].strip(), f.read().split("\n")[2:]))[:-1]

def get_wireless_interfaces():
    """
    """
    ifaces = get_interfaces()
    return list(filter(lambda iface: "wlan" in iface, ifaces))

def monitor_interface_available():
    iw = get_wireless_interfaces() #wireless interfaces
    mon_iw = list(filter(lambda iface: "mon" in iface, iw)) #get wireless interfaces in monitor mode
    return len(mon_iw) > 0

class Mode(Enum):
        MANAGED = 1
        MONITOR = 2

class Interface:

    def __init__(self, name: str, mode:Mode = Mode.MANAGED):
        self.mode = mode

        if mode == Mode.MONITOR:
            self.name = name[:-3] #assuming it follows this pattern of ending monitoring interfaces with 'mon'
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


monitor_iface = Interface(INTERFACE)


if __name__ == "__main__":
    iface = Interface("wlan1mon", Mode.MONITOR)
    iface.disable_monitor_mode()