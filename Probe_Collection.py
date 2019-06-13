#!/usr/bin/env python
##

import os
import sys
import time
import itertools
import netifaces
from gps import *
from netaddr import EUI 
from itertools import cycle
from scapy.all import sniff, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt, Dot11Beacon
from subprocess import call
from threading import Thread

known_essid_list=[""]

## Global Vars
os.environ['TZ'] = 'US/Eastern'
#chans=['1','3','6','9','11','12','14']
chans=['1','6','11','14']
#chans=['1']
devices=[]
beacon_lookback = []
probe_lookback = []
bssid_whitelist=[]

logfile="/var/log/probe_log"
try:
    lf=open(logfile,'a', 0)
except:
    sys.exit()

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
            print("Setting time by GPS")
            gpsutc = gps.utc[0:4] + gps.utc[5:7] + gps.utc[8:10] + ' ' + gps.utc[11:19]
            set_string = '--set=' + gpsutc
            call(['/bin/date', '-u', set_string])
            break

def gps_watch():
        try:
	    while True:
	    	gps.next()
                time.sleep(0.2)
        except:
            pass

def gps_thread():
    thread = Thread(target=gps_watch)
    thread.daemon = True
    thread.start()

def enable_mon():
    for iface in netifaces.interfaces():
        if "wlan" in iface:
              devices.append(iface)
    if len(devices) == 0:
        print "No usable interface found."
        sys.exit()
    elif len(devices) > 1:
        if "wlan0" in devices:
            print "Off board USB detected. Skipping onboard WiFi."
            del devices[devices.index("wlan0")]
    for device in devices:
        if device == "wlan0":
                try:
                    call(['/sbin/iw', 'phy', 'phy0', 'interface', 'add', 'mon0', 'type', 'monitor'])
                except:
       	            print "No usable interface found."
                    sys.exit()
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
        if len(beacon_lookback) > 10:
            del beacon_lookback[0]
        else:
            break
    beacon_lookback.append(bssid)
    #print(str(beacon_lookback))

def update_probe_lookback(bssid):
    while True:
        if len(probe_lookback) > 10:
            del probe_lookback[0]
        else:
            break
    probe_lookback.append(bssid)
    #print(str(probe_lookback))

def update_bssid_whitelist(essid,bssid):
    if essid in known_essid_list:
        if bssid not in bssid_whitelist:
            bssid_whitelist.append(bssid)
    while True:
        if len(bssid_whitelist) > 100:
            del bssid_whitelist[0]
        else:
            break

def phandle(p): 
    if p.haslayer(Dot11ProbeReq): 
        ptime=time.strftime("%Y-%m-%d %H:%M:%S %Z")
        bssid = str(p.addr2)
        if p.haslayer(Dot11Elt): 
            ssid = p[Dot11Elt].info 
        else:
            ssid = ""
        if str(bssid) in probe_lookback:
            return
        elif str(ssid) in known_essid_list:
            update_probe_lookback(bssid)
        try:
            lat = str(gps.fix.latitude)
        except:
            lat = "NA"
        try:
            lon = str(gps.fix.longitude)
        except:
            lon = "NA"
        try:
            maco = EUI(bssid)
            macf = maco.oui.registration().org 
        except:
            macf = "NA"
            pass
        log_string = "PROBE;" + ptime + ";" + lat + ";" + lon + ";" + bssid + ";" + macf + ";" + ssid + ";" + "\n"
        lf.write(log_string) 
        print log_string
    elif ( p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)):
        ptime=time.strftime("%Y-%m-%d %H:%M:%S %Z")
        bssid = str(p.addr3)
        if str(bssid) in beacon_lookback:
            return
        else:
            update_beacon_lookback(bssid)
        if p.haslayer(Dot11Elt): 
            ssid = p[Dot11Elt].info 
        else:
            ssid = ""
        try:
            lat = str(gps.fix.latitude)
        except:
            lat = "NA"
        try:
            lon = str(gps.fix.longitude)
        except:
            lon = "NA"
        try:
            maco = EUI(bssid)
            macf = maco.oui.registration().org 
        except:
            macf = "NA"
            pass
        #if p.haslayer(Dot11Elt): 
        #    ssid = p[Dot11Elt].info 
        #else:
        #    ssid = ""
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%} {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        if "+privacy" in capability:
            enc = 'Y'
        else: 
            enc  = 'N'
        log_string = "AP;" + ptime + ";" + lat + ";" + lon + ";" + bssid + ";" + macf + ";" + ssid + ";" + enc + "\n"
        lf.write(log_string) 
        print log_string

            
def rotate_chans():
    if "mon0" in devices:
        if len(devices) == 1:
            print "Onboard WiFi Only. Channel hopping is disabled."
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
            print(device + " channel set to " + chan + ".") 
            time.sleep(10)

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
        time.tzset()
        gps_setup()
        set_time()
	gps_thread()
        enable_mon()
	print devices
        channel_thread()
        start_sniff()
    	lf.close()
