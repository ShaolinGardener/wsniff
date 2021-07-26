import scapy.all as scapy

class Frame:
    """
    Format that is more intuitive to use (also reduces coupling because we are now more independant from other libraries, so 
    it is easer to switch them)
    """

    TO_DS = 0x1
    FROM_DS = 0x2
    DOT11_FRAME_TYPE_MANAGEMENT = 0
    DOT11_FRAME_TYPE_CONTROL = 1
    DOT11_FRAME_TYPE_DATA = 2

    def __init__(self, frame, channel=0, iface=None):
        self.frame = frame
        
        self.bssid = None
        self.ssid = None
        self.signal_strength = 0
        self.channel = channel
        self.iface = iface
        self.frame_bytes = len(frame)

        # DS = Distribution System; wired infrastructure connecting multiple BSSs to form an ESS
        # decode addresses 1 to 4
        #FC: frame Control
        to_ds = frame.FCfield & Frame.TO_DS != 0
        from_ds = frame.FCfield & Frame.FROM_DS != 0
        if to_ds and from_ds:
            self.dst = frame.addr3
            self.src = frame.addr4
            self.macs = {frame.addr1, frame.addr2, frame.addr3, frame.addr4}
        elif to_ds:
            self.src = frame.addr2
            self.dst = frame.addr3
            self.bssid = frame.addr1
            self.macs = {frame.addr2, frame.addr3}
        elif from_ds:
            self.src = frame.addr3
            self.dst = frame.addr1
            self.bssid = frame.addr2
            self.macs = {frame.addr1, frame.addr3}
        else:
            self.dst = frame.addr1
            self.src = frame.addr2
            self.bssid = frame.addr3
            self.macs = {frame.addr1, frame.addr2}

        if (frame.haslayer(scapy.Dot11Elt) and
                (frame.haslayer(scapy.Dot11Beacon) or frame.haslayer(scapy.Dot11ProbeResp))):

            try:
                self.ssid = frame[scapy.Dot11Elt].info.decode().replace("\x00", "[none]")
            except UnicodeDecodeError:
                # Only seems to happen on macOS - probably some pcap decoding bug
                self.ssid = None

        if frame.haslayer(scapy.RadioTap):
            #old solution: https://stackoverflow.com/questions/10818661/scapy-retrieving-rssi-from-wifi-packets
            #has been fixed now you don't have to use decoded part of packet but can use dBm_AntSignal
            self.signal_strength = frame[scapy.RadioTap].dBm_AntSignal

    def frame_type(self):
        """Returns the 802.11 frame type."""
        return self.frame.type

    def frame_type_name(self):
        """Returns the type of frame - "management", "control", "data", or "unknown"."""
        if self.frame.type == self.DOT11_FRAME_TYPE_MANAGEMENT:
            return "management"
        elif self.frame.type == self.DOT11_FRAME_TYPE_CONTROL:
            return "control"
        elif self.frame.type == self.DOT11_FRAME_TYPE_DATA:
            return "data"
        return "unknown"

    def __str__(self):
        return "Dot11 (type={}, from={}, to={}, bssid={}, ssid={}, signal_strength={})".format(
            self.frame_type_name(), self.src, self.dst, self.bssid, self.ssid, self.signal_strength)

    def __repr__(self):
        return self.__str__()



if __name__ == "__main__":
    packets = scapy.rdpcap("./cap.pcap")
    for i in range(10):
        p = Frame(packets[i])
        print(p)