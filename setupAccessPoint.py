import os
import sys
import subprocess

NC='\033[0m' #no color/back to default
RED='\033[0;31m'
GREEN='\033[0;32m'
def execute_shell_cmd(cmd: str, input=None):
    """
    Execute a shell command and print error messages in case it failed.
    """
    print("[*] Trying to run:", cmd)
    try:
        proc_res = subprocess.run(cmd, text=True, capture_output=True, input=input, shell=True, check=True)
        res = proc_res.stdout
        if res:
            print(f"{GREEN}[+]{NC}", res)
        else:
            print(f"{GREEN}[+]{NC} Done")
        return res
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-]{NC} '", e.cmd, "' failed with return code ",  e.returncode, sep="")
        print(e.stderr)
        print(f"{RED}[-] Please resolve this issue before restarting this script.")
        sys.exit()

def append_to_file(filename: str, content: str):
    """
    If the file does not exist yet, it will be created.
    """
    print("[*] Writing to file:", filename)
    f = None
    try:
        f = open(filename, "a")
        f.write(f"\n{content}")
    except Exception as e:
        print(f"{RED}[-] Error occured:{NC}\n", e)
        print("[*] Note: maybe you didn't run this script with sudo ...")
        sys.exit()
    finally:
        if f:
            f.close()


install_cmds=[
    "sudo apt install hostapd",
    "sudo systemctl unmask hostapd",
    "sudo systemctl enable hostapd",
    "sudo apt install dnsmasq",
    "sudo DEBIAN_FRONTEND=noninteractive apt install -y netfilter-persistent iptables-persistent"
]

dhcpcd_conf = \
"""interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant\n"""

routed_ap_conf = \
"""# Enable IPv4 routing
net.ipv4.ip_forward=1\n"""

dnsmasq_conf = \
"""interface=wlan0 # listening interface (internal card)
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
                # Pool of IP addresses served via DHCP
domain=wlan     # Local wireless DNS domain
address=/wsniff.com/192.168.4.1 #alias for this router\n"""

hostapd_conf = \
"""country_code={country_code}
interface=wlan0
ssid=wsniff
hw_mode=g
channel=7
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=feedmepackets
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP"""


def main():
    #check the script is run with sudo
    if not os.geteuid() == 0:
        print(f"{RED} [-] You have to run this script with root priviledges:{NC} 'sudo python3 setupAccessPoint.py'")
        sys.exit()

    #get wifi country code - it is necessary to set up the access point
    country_code = None
    with open("/etc/wpa_supplicant/wpa_supplicant.conf", "r") as f:
        content = f.readlines()
        for line in content:
            if "country" in line:
                country_code = line[8:10]
                break
        if country_code == None:
            print(f"{RED} [-] No Wi-Fi country set. Please set a country using 'sudo raspi-config'.")
            sys.exit()

    print(f"{GREEN}[*]{NC} Your Wi-Fi country seems to be set to: ", country_code)


    #install necessary software
    for install in install_cmds:
        #Y simulating the user's agreement to the installation
        execute_shell_cmd(install, "Y")
    print(f"{GREEN}[+] Every installation was successful.{NC}")

    #configure stuff:
    append_to_file("/etc/dhcpcd.conf", dhcpcd_conf)
    append_to_file("/etc/sysctl.d/routed-ap.conf", routed_ap_conf)

    #enable NAT routing
    execute_shell_cmd("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    execute_shell_cmd("sudo netfilter-persistent save")

    #configure DHCP/DNS services provided by dnsmasq
    execute_shell_cmd("sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig")
    append_to_file("/etc/dnsmasq.conf", dnsmasq_conf)


    append_to_file("/etc/hostapd/hostapd.conf",
                    hostapd_conf.format(country_code=country_code))

    print(f"{GREEN}[+] Success. Reboot now ('sudo systemctl reboot').")



if __name__=="__main__":
    main()
