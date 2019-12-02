#!/usr/bin/env python
##

import os
import sys
import time
import itertools
import RPi.GPIO as GPIO
import time
from itertools import cycle
from subprocess import call
from threading import Thread

## Global Vars
os.environ['TZ'] = 'US/Eastern'

## Traffic Light Vars
red = 26
amber = 21
green = 20
light_lock = {}
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(red,GPIO.OUT)
GPIO.setup(amber,GPIO.OUT)
GPIO.setup(green,GPIO.OUT)

seq = [7,4,3,6,1,7,7,7,3,2,4]

def run_squence(seq):
    for c in seq:
        if c & 1: 
            rlight_on()
        else:
            rlight_off()
        if c & 2: 
            alight_on()
        else:
            alight_off()
        if c & 4: 
            glight_on()
        else:
            glight_off()
        time.sleep(1)
            

logfile="/var/log/traffic_light_sequencer_log"
try:
    lf=open(logfile,'a', 0)
except:
    sys.exit()

def all_off():
    GPIO.output(red,GPIO.HIGH)
    GPIO.output(amber,GPIO.HIGH)
    GPIO.output(green,GPIO.HIGH)

def rlight_on():
           GPIO.output(red,GPIO.LOW)
           return

def rlight_off():
           GPIO.output(red,GPIO.HIGH)
           return

def alight_on():
           GPIO.output(amber,GPIO.LOW)
           return

def alight_off():
           GPIO.output(amber,GPIO.HIGH)
           return

def glight_on():
           GPIO.output(green,GPIO.LOW)
           return

def glight_off():
           GPIO.output(green,GPIO.HIGH)
           return

def header():
    print("Type;Date;Lat;Lon;BSSID;Manufacturer;SSID;Encryption")
    lf.write("Type;Date;Lat;Lon;BSSID;Manufacturer;SSID;Encryption\n")
    

# our main function 
if __name__ == "__main__":
        all_off()
    	lf.close()
        #while True:
        run_squence(seq)
        all_off()
