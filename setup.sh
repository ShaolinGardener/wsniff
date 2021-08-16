#setup virtual environment for python
python3 -m venv venv
#install required libraries
source ./venv/bin/activate
pip install -r ./res/requirements.txt

# Install BCM2835 libraries
wget http://www.airspayce.com/mikem/bcm2835/bcm2835-1.60.tar.gz
tar zxvf bcm2835-1.60.tar.gz
cd bcm2835-1.60/
./configure
make
make check
make install
#delete files
cd .. #back to wsniff directory
rm -Rf bcm2835-1.60*

#numpy needs OpenBLAS for linear algebra, if you install numpy via PyPI it
#is expected you install a corresponding package yourself
sudo apt-get install libatlas-base-dev

#Create a new empty database
./venv/bin/python init_db.py

