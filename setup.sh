#=====================================BASIC PI CONFIG CHANGES===================================
#enable SPI (0:enabled, 1:disabled)
sudo raspi-config nonint do_spi 0
#enable serial interface (/dev/serial0), disable serial login shell
sudo raspi-config nonint do_serial 2
#===============================================================================================


#=====================================INSTALL PYTHON PACKAGES===================================
#setup virtual environment for python
python3 -m venv venv
#install required libraries
source ./venv/bin/activate
pip install -r ./res/requirements.txt
#===============================================================================================

#=====================================INSTALL OTHER STUFF WE NEED===============================
# Install BCM2835 libraries
wget http://www.airspayce.com/mikem/bcm2835/bcm2835-1.60.tar.gz
tar zxvf bcm2835-1.60.tar.gz
cd bcm2835-1.60/
sudo ./configure
sudo make
sudo make check
sudo make install
#delete files
cd .. #back to wsniff directory
sudo rm -Rf bcm2835-1.60*

#numpy needs OpenBLAS for linear algebra, if you install numpy via PyPI it
#is expected you install a corresponding package yourself
sudo apt-get install libatlas-base-dev
#===============================================================================================


