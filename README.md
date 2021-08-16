<p align="center">
  <img alt="wsniff" src="https://user-images.githubusercontent.com/25824942/129544376-a2619d07-e764-4c78-bf38-339fa8d99240.jpg" height="200" />
  <p align="center">
    <img alt="version" src="https://img.shields.io/badge/version-1.1-brightgreen?style=for-the-badge&labelColor=6d6157" />
    <img src="https://img.shields.io/badge/uses-python3-brightgreen?style=for-the-badge&logo=python&logoColor=white&labelColor=6d6157" />
  </p>
</p>

# wsniff
A WiFi sniffer you can use with your Raspberry Pi and simply control over your smartphone - discover 802.11 networks, capture their traffic or create interactive wardriving maps. The all-in-one solution with a comfortable
 graphical user interface. 🌱
 
## Requirements
You will need:
- a Raspberry Pi (at least the 3B version)
- a GPS module connected to the Pi in case you want to use the wardriving functions
- a USB WiFi adapter that supports monitor mode (otherwise sniffing would not make sense anyway)

## Setup
- Clone the project from Github
```
cd <path_to_install_to>
git clone https://github.com/JulianWindeck/wsniff wsniff
```
- Create a virtual environment for python 
```
cd wsniff
python3 -m venv venv //could also be python, depends on your alias
source ./venv/bin/activate
pip install -r ./res/requirements.txt
deactivate
```

In theory, you are now ready to go, but in order to be able to control your sniffer with your smartphone
or another mobile device, you should set up the internal WiFi card of the Pi as an Access Point. 
For that, just follow the [official manual](https://www.raspberrypi.org/documentation/computers/configuration.html#setting-up-a-routed-wireless-access-point).
After a reboot, you should be able to connect to the new wireless network of the Raspberry.

## Start wsniff
Be sure you are in the wsniff directory which you cloned from Github.

Then, you can start wsniff with `sudo ./venv/bin/python main.py`.
After you have executed that command, you can use the browser of the device you have connected to the Pi in the previous step and type in the Pi's IP-address.
Now the web interface of wsniff should appear.

## Adapt wsniff
- After the installation of new packages you should update requirements.txt:
```
pip freeze > ./res/requirements.txt
```

- For changes on the design activate the automatic transpilation of Sass: 
```
sass --watch ./sass:./css //zum Abbrechen im Terminal Ctrl-C
```

