from capture import *
from website.interfaces import Interface

def test_capture():
    start_capture("blub", 11, interface="wlan0mon")
    start_capture("2", 2, interface="wlan0mon")
    stop_capture("blub")
    stop_capture("2")

def test_interface():
    iface = Interface("wlan1")
    iface.enable_monitor_mode()
    iface.set_channel(7)

if __name__ == "__main__":
    test_interface()