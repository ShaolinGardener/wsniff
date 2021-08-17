<p align="center">
  <img alt="wsniff" src="https://user-images.githubusercontent.com/25824942/129544376-a2619d07-e764-4c78-bf38-339fa8d99240.jpg" height="200" />
  <p align="center">
    <img alt="version" src="https://img.shields.io/badge/version-1.1-brightgreen?style=for-the-badge&labelColor=6d6157" />
    <img src="https://img.shields.io/badge/uses-python3-brightgreen?style=for-the-badge&logo=python&logoColor=white&labelColor=6d6157" />
  </p>
  <div align="center">Built with ❤️&nbsp; by <a href="https://github.com/JulianWindeck">julian</a></div>
</p>

# wsniff [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Discover%20and%20sniff%20WiFi%20networks%20with%20wsniff!&url=https://github.com/JulianWindeck/wsniff&hashtags=dot11,security,wsniff,sniffing)
A WiFi sniffer you can use with your Raspberry Pi and simply control over your smartphone - discover 802.11 networks, capture their traffic or create interactive wardriving maps. The all-in-one solution with a comfortable
 graphical user interface. 🌱
 
## Table of Contents
- [Requirements](#-requirements)
- [Setup](#setup)
- [Run the software](#start-wsniff)
- [Adapt wsniff](#-adapt-wsniff)
- [Licence](#-licence)
 
## 📝 Requirements
You will need:
- a Raspberry Pi (at least the 3B version)
- a GPS module connected to the Pi in case you want to use the wardriving functions
- a USB WiFi adapter that supports monitor mode (otherwise sniffing would not make sense anyway)

## Setup 
0. This step is only necessary if you use a fresh install of Raspberry Pi OS. Then, your Wi-Fi might be blocked by rfkill.
In order to fix this, use raspi-config to set the country before use:
```sh
sudo raspi-config
```
In this dialog, first choose 'Localization Options' and then 'WLAN Country'. Here you should select your country and then confirm your choice by pressing \<Enter\>. After that, you can exit the settings menu by pressing \<Escape\>.

1. Clone the project from Github
```sh
cd <path_to_install_to>
git clone https://github.com/JulianWindeck/wsniff 
```
2. Install the software 
```
cd wsniff
./setup.sh
```

3. Now, you have to reboot:
```sh
sudo reboot 
```

In theory, you are now ready to go and [can start the software](#start-wsniff).
However, if you want to be able to control your sniffer with your smartphone
or another mobile device, you should set up the internal WiFi card of the Pi as an Access Point. 
For that, just follow the [official manual](https://www.raspberrypi.org/documentation/computers/configuration.html#setting-up-a-routed-wireless-access-point).
After a reboot, you should be able to connect to the new wireless network of the Raspberry.

## Start wsniff
Be sure you are in the wsniff directory which you cloned from Github.

Then, you can start wsniff with:
```sh
sudo ./venv/bin/python main.py
```
After you have executed that command, you can use the browser of the device you have connected to the Pi in the previous step and type in the Pi's IP-address.
Now the web interface of wsniff should appear where you should create a new account first.
![image](https://user-images.githubusercontent.com/25824942/129654364-5bd494c1-0d1a-49d3-96d1-8eb76f97cc8d.png)


## 🖋 Adapt wsniff
- After the installation of new packages you should update requirements.txt:
```sh
pip freeze > ./res/requirements.txt
```

- For changes on the design activate the automatic transpilation of Sass: 
```sh
sass --watch ./sass:./css //zum Abbrechen im Terminal Ctrl-C
```

## 📖 Licence
[GNU General Public License v3.0](https://github.com/JulianWindeck/wsniff/blob/main/LICENSE.md)
