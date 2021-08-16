from abc import ABC, abstractmethod
import sys
import os

import logging
from display.waveshare import epd2in13_V2
import time
from PIL import Image, ImageDraw, ImageFont
from threading import Thread

from website.settings import DISPLAY_ENABLED

logging.basicConfig(level=logging.DEBUG)

#init
picdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'res')
font15 = ImageFont.truetype(os.path.join(picdir, 'Font.ttc'), 15)
font24 = ImageFont.truetype(os.path.join(picdir, 'Font.ttc'), 24)


class Display(ABC):
    @abstractmethod
    def draw_string(self, str, x, y):
        pass

    @abstractmethod
    def draw_image(self, img_filename: str):
        pass

    @abstractmethod
    def sleep(self):
        pass

    @abstractmethod
    def wakeup(self):
        pass

    @abstractmethod
    def clear(self):
        pass

    @abstractmethod
    def shutdown(self):
        pass

    @abstractmethod
    def enable_partial():
        pass

    @abstractmethod
    def draw_string_partial(text, x, y):
        pass

    @abstractmethod
    def disable_partial():
        pass

"""
A GhostDisplay object is used in case the raspberry pi is not using a
display. This way, we don't have to add a ton of if-statements in other
code to check whether there is really a display.
"""
class GhostDisplay():
    def draw_string(self, str, x, y):
        pass

    def draw_image(self, img_filename: str):
        pass

    def sleep(self):
        pass

    def wakeup(self):
        pass

    def clear(self):
        pass

    def shutdown(self):
        pass

    def enable_partial():
        pass

    def draw_string_partial(text, x, y):
        pass

    def disable_partial():
        pass


"""
This class actually encapsulates the waveshare e-ink display.
"""
class RealDisplay():
    def __init__(self):
        #this should be called on initialization
        #create E-Paper-Display object
        self.epd = epd2in13_V2.EPD()
        self.wakeup()
        #clear screen
        self.clear()

    #HINWEIS: resolution ist 250*122
    def draw_string(self, str, x, y):
        self.wakeup()
        image = Image.new('1', (self.epd.height, self.epd.width), 255)  # 255: clear the frame
        draw = ImageDraw.Draw(image)

        draw.text((x, y), str, font = font24, fill = 0)
        self.epd.display(self.epd.getbuffer(image))
        self.sleep()

    def draw_image(self, img_filename: str):
        """
        img_filename: filename of image relative to res/
        """
        self.wakeup()
        image = Image.open(os.path.join(picdir, img_filename))
        self.epd.display(self.epd.getbuffer(image))
        self.sleep()

    def sleep(self):
        """
        turn epaper into sleep mode
        if you don't refresh the epaper for a longer time or disconnect it from the raspberry
        this is really imporant because otherwise the epaper will have ghosting problems after some days
        (e-Paper is damaged because of working in high voltage for long time)
        """
        self.epd.sleep()

    def wakeup(self):
        """
        after display has been set to sleep mode, you have to call wakeup before displaying new information
        """
        self.epd.init(self.epd.FULL_UPDATE)

    def clear(self):
        """
        used to clear epaper (to white)
        """
        self.epd.Clear(0xFF)

    def shutdown(self):
        self.wakeup()
        self.clear()
        self.epd.Dev_exit()

    def enable_partial():
        self.image = Image.new('1', (epd.height, epd.width), 255)
        self.draw = ImageDraw.Draw(self.image)

        wakeup()
        self.epd.displayPartBaseImage(epd.getbuffer(self.image))
        #set to partial update mode
        self.epd.init(epd.PART_UPDATE)

    def draw_string_partial(text, x, y):
        self.draw.rectangle((x, y, 220, 105), fill = 255)
        self.draw.text((x, y), text, font = font24, fill = 0)
        self.epd.displayPartial(epd.getbuffer(self.image))

    def disable_partial():
        wakeup()
        clear() #not necessary

    def __del__(self):
        self.shutdown()



#now for calls from the outside
if DISPLAY_ENABLED:
    display = RealDisplay()
else:
    display = GhostDisplay()

def wait(t: int):
    time.sleep(t)

def _startup():
    display.draw_image("wsniff.bmp")
    wait(5)
    display.draw_image("wifi.bmp")

def startup():
    t = Thread(target=_startup)
    t.start()

def enable_partial_update():
    display.enable_partial()

def partial_update(text, x, y):
    display.draw_string(text, x, y)

def shutdown():
    display.draw_image("shutdown.bmp")
    wait(4)
    display.shutdown()

def main():
    startup()
    shutdown()


if __name__ == "__main__":
    main()
