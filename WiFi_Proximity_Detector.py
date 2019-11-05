#!/usr/bin/env python

##################################
##                               #
## Author: Philip Bertugia       #
## Date: 10/01/2019              #
##   First rev closer to 2017.   #
##                               #
## Desc:                         # 
## I have a traffic light.       #
## What would you do?            #
## Listens for wifi probes and   #
## alerts for unknowns via GPIO  #
## and relay board on a RPi.     # 
##                               #
##################################

import os
import sys
import time
import itertools
import netifaces
import RPi.GPIO as GPIO
import time
from gps import *
from netaddr import EUI 
from itertools import cycle
from scapy.all import *
#from scapy.all import sniff, Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt, Dot11Beacon
from subprocess import call
from threading import Thread

## Global Vars
os.environ['TZ'] = 'US/Eastern'
#chans=['1','3','6','9','11','12','14']
chans=['1','6','9','11',]
devices=[]
#chans=['1']
#a_list = ['5c:aa:fd:f8:5a:23']
a_list = []
w_ssid_list = ['AAOOJVWKS_5GHz',
        'AAOOJVWEW_2Gz',
        'not-free',
        'CSN',
        'hospinet'
        ]
b_ssid_list = ['Paracelsus']
w_macf_list = ['AzureWave Technology Inc.']

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


logfile="/var/log/probe_log"
try:
    lf=open(logfile,'a', 0)
except:
    sys.exit()

def write(pkt):
        wrpcap('/var/log/probelog.pcap', pkt, append=True)

### GPS Functions ###
def gps_setup():
    try: 
        ## lobal for GPS polling thread. 
        global gps
        gps = gps(mode=WATCH_ENABLE)
    except:
        print("No GPS.")
        sys.exit()

def set_time():
    while True:
        gps.next()
        if gps.utc != None and gps.utc != '':
            gpsutc = gps.utc[0:4] + gps.utc[5:7] + gps.utc[8:10] + ' ' + gps.utc[11:19]
            set_string = '--set=' + gpsutc
            call(['/bin/date', '-u', set_string])
            break

def gps_watch():
        try:
            set_time()
	    while True:
	    	gps.next()
                time.sleep(0.2)
        except:
            pass

def gps_thread():
    thread = Thread(target=gps_watch)
    thread.daemon = True
    thread.start()

def start_flash_thread(c):
    if( c in light_lock.keys()):
        return
    if(c == "red"):
        thread = Thread(target=flash_rlight)
    elif(c == "amber"):
        thread = Thread(target=flash_alight)
    elif(c == "green"):
        thread = Thread(target=flash_glight)
    thread.daemon = True
    thread.start()


def all_off():
    GPIO.output(red,GPIO.HIGH)
    GPIO.output(amber,GPIO.HIGH)
    GPIO.output(green,GPIO.HIGH)

def flash_rlight():
        try:
            light_lock["red"] = True
            for fl in range(0,5):
                GPIO.output(red,GPIO.LOW)
                time.sleep(30)
                GPIO.output(red,GPIO.HIGH)
                del light_lock["red"]
        except:
            return

def flash_alight():
        try:
            light_lock["amber"] = True
            for fl in range(0,5):
                GPIO.output(amber,GPIO.LOW)
                time.sleep(10)
                GPIO.output(amber,GPIO.HIGH)
                del light_lock["amber"]
        except:
            return

def flash_glight():
        try:
            light_lock["green"] = True
            for fl in range(0,5):
                GPIO.output(green,GPIO.LOW)
                time.sleep(5)
                GPIO.output(green,GPIO.HIGH)
                del light_lock["green"]
        except:
            return

def enable_mon():
    for iface in netifaces.interfaces():
        if "wlan" in iface:
              devices.append(iface)
    if len(devices) == 0:
        print "No usable interface found."
        sys.exit()
    elif len(devices) > 1:
        if "wlan0" in devices:
            print "USB WiFi device detected. Skipping onboard WiFi configruation."
            del devices[devices.index("wlan0")]
    for device in devices:
        if device == "wlan0":
                try:
                    call(['/sbin/iw', 'phy', 'phy0', 'interface', 'add', 'mon0', 'type', 'monitor'])
                except:
                    pass 
                if "mon0" in netifaces.interfaces():
                    devices.append("mon0")
                    del devices[devices.index("wlan0")]
                    call(['/sbin/ifconfig', "mon0", 'up'])
                else:
                    call(['/sbin/iwconfig', device, 'mode', 'monitor'])
        elif device != "mon0":
            call(['/sbin/iwconfig', device, 'mode', 'monitor'])
            call(['/sbin/ifconfig', device, 'up'])

def update_beacon_lookback(bssid):
    while True:
        if len(beacon_lookback) > 20:
            del beacon_lookback[0]
        else:
            break
    beacon_lookback.append(bssid)

def phandle(p): 
    if p.haslayer(Dot11ProbeReq): 
    #    try:
    #        wrpcap('/var/log/probelog.pcap', p, append=True)
    #    except:
    #        pass
        bssid = str(p.addr2)
        ptime=time.strftime("%Y-%m-%d %H:%M:%S %Z")
        ssid = ""
        macf = ""
        has_apple = False
        has_broadcom = False
        alert_c = ""
        if p.haslayer(Dot11Elt):
            ssid = p.info
            try:
                maco = EUI(bssid)
                macf = maco.oui.registration().org 
            except:
                pass
            if ssid != "":
               # for w_ssid in w_ssid_list:
                if str(ssid) in b_ssid_list:
                    alert_c = "red"
                elif str(ssid) not in w_ssid_list:
                       alert_c = "amber"
            elt = p.getlayer(Dot11Elt)
            ## iOS randomizes WiFi MACs. Just skip them for now.
            while elt:
                if elt.ID == 221:
                    if elt.info == '\x00\x17\xf2\n\x00\x01\x04\x00\x00\x00\x00':
                        has_apple = True
                    if elt.info == '\x00\x10\x18\x02\x00\x00\x10\x00\x00':
                        has_broadcom = True
                elt = elt.payload.getlayer(Dot11Elt)
            if has_apple and has_broadcom:
                macf = "iOS"
            elif has_apple:
                macf = "Apple"
            elif macf != "":
                if macf not in w_macf_list:
                    alert_c = "amber"
        if alert_c != "":
            start_flash_thread(alert_c)
            print(alert_c + ": " + bssid)
        try:
            lat = str(gps.fix.latitude)
        except:
            lat = "NA"
        try:
            lon = str(gps.fix.longitude)
        except:
            lon = "NA"
        log_string = "PROBE;" + ptime + ";" + lat + ";" + lon + ";" + bssid + ";" + macf + ";" + ssid + ";" + "\n"
        lf.write(log_string) 
        print log_string
            
def rotate_chans():
    if "mon0" in devices:
        if len(devices) == 1:
            print "Onboard WiFi Only. Channel hopping disabled."
            return
    toggle = itertools.cycle(devices).next
    while True:
        for chan in chans:
            device=toggle()
            if device == "mon0":
                device=toggle()
            try:
                call(['/sbin/iwconfig', device, 'channel', chan])
            except:
                pass
            print(device + " set to channel " + chan + ".") 
            time.sleep(5)

def channel_thread():
    thread = Thread(target=rotate_chans)
    thread.daemon = True
    thread.start()

def start_sniff():
#   header()
    print("Starting sniff on :" + str(devices))
    sniff(iface=devices,prn=phandle, store=0)

def header():
    print("Type;Date;Lat;Lon;BSSID;Manufacturer;SSID;Encryption")
    lf.write("Type;Date;Lat;Lon;BSSID;Manufacturer;SSID;Encryption\n")
    

# our main function 
if __name__ == "__main__":
        #time.tzset()
        #gps_setup()
	#gps_thread()
        all_off()
        enable_mon()
        channel_thread()
        start_sniff()
    	lf.close()
