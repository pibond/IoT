#!/usr/bin/env python
##http://www.devx.com/security/Article/34741/0/page/5
##https://www.sans.org/reading-room/whitepapers/detection/detecting-responding-data-link-layer-attacks-33513
##https://github.com/DanMcInerney/wifijammer/blob/master/wifijammer.py
##https://www.sans.org/reading-room/whitepapers/wireless/programming-wireless-security-32813
##http://www.rpiblog.com/2012/09/using-gpio-of-raspberry-pi-to-blink-led.html
##http://stackoverflow.com/questions/10818661/scapy-retrieving-rssi-from-wifi-packets
##
## Authors: Philip Bertuglia 
## Date:    February 18, 2018
##
## See the README file for a full decription.
## 

import sys, re, time
from scapy.all import *
from collections import Counter
from threading import Thread
from subprocess import call
import RPi.GPIO as GPIO
import numpy
import Adafruit_GPIO.SPI as SPI
import Adafruit_SSD1306
import netifaces
import itertools
from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont

## OLED display initialization.
RST = None     # on the PiOLED this pin isnt used
disp = Adafruit_SSD1306.SSD1306_128_32(rst=RST)
disp.begin()
width = disp.width
height = disp.height
image = Image.new('1', (width, height))
draw = ImageDraw.Draw(image)
disp.display()
draw.rectangle((0,0,width,height), outline=0, fill=0)
disp.display()
padding = -2
top = padding
bottom = height-padding
x = 0
font = ImageFont.load_default()

## LED Pins, BCM
red_led = 26
green_led = 13
detect_led = red_led
status_led = green_led

## Other Global Variables.

devices = []

def led_init():
	GPIO.setmode(GPIO.BCM)
	GPIO.setwarnings(False)
	GPIO.setup(status_led, GPIO.OUT)
	GPIO.setup(detect_led, GPIO.OUT)
	all_off()

def all_off():
        GPIO.output(detect_led, False)
        GPIO.output(status_led, False)

def flash_detect():
	GPIO.output(detect_led, True)
	while( detect_led_rate != 0 ):
		if( detect_led_rate == -1 ):
			time.sleep(.01)
			continue
		else:
			GPIO.output(detect_led, True)
			time.sleep(detect_led_rate)
        		GPIO.output(detect_led, False)
			time.sleep(detect_led_rate)
	return
	
def flash_status(packets,c,status):
        if status == "OK":
            GPIO.output(detect_led, False)
            GPIO.output(status_led, True)
            time.sleep(.01)
            GPIO.output(status_led, False)
	    draw.rectangle((0,0,width,height), outline=0, fill=0)
	    draw.text((x, top), "Chan:  " + str(c),  font=font, fill=255)
	    draw.text((x, top+8), "Frames: " + str(packets), font=font, fill=255) 
	    draw.text((x, top+17), "Status: OK", font=font, fill=255) 
	    disp.image(image)
	    disp.display()	
        else:
            GPIO.output(detect_led, True)
	    draw.rectangle((0,0,width,height), outline=0, fill=0)
	    draw.text((x, top), "Chan:  " + str(c),  font=font, fill=255)
	    draw.text((x, top+17), "Status: " + str(status), font=font, fill=255) 
	    disp.image(image)
	    disp.display()	

# LED meter:
# 1. Grab a frame using a BSSID as the filter.
# 2. Get the if included powerlevel 
# 3. Output to OLED dispaly RSSI and BSSID
# 4. Repeat. 
def meter(bssid, essids, device):
	start = time.time()
	timeout = 15
        filter_string = "ether src " + str(bssid)
	global detect_led_rate
	detect_led_rate = -1
	flash_detect_t = Thread(target=flash_detect)
	flash_detect_t.start()
	GPIO.output(detect_led, True)
	while ( time.time() - start < timeout ):
       		pkts = sniff(iface=device, filter=filter_string, count=1, timeout=1)
		if ( len(pkts) != 0 ):
			if ( pkts[0].haslayer(Dot11) and hasattr(pkts[0].getlayer(Dot11),'addr3') ):
				if ( str(pkts[0].getlayer(Dot11).addr3) == bssid ):
					rssi = -(256-ord(pkts[0].notdecoded[-4:-3]))
					print "BSSID: " + str(pkts[0].getlayer(Dot11).addr3)
					print "ESSIDs: " + essids
					print "RSSI: " + str(rssi)
				else:
					continue
			else:
				continue
		else:
			continue
		if ( rssi > -28 ):
			detect_led_rate = 0.1 
		elif ( rssi > -35 ):
			detect_led_rate = 0.5 
		elif ( rssi > -60 ):
			detect_led_rate = 1
		draw.rectangle((0,0,width,height), outline=0, fill=0)
		draw.text((x, top),       str(bssid),  font=font, fill=255)
		draw.text((x, top+8),     essids, font=font, fill=255)
		draw.text((x, top+20),     "RSSI: " + str(rssi), font=font, fill=255)
		disp.image(image)
		disp.display()	
	detect_led_rate = 0
	return

def collectInfo(p):
        type=[]
        subtype=[]
        addr1=[]
        addr2=[]
        addr3=[]
        essid=[]
        for i in range(0,len(p)):
                if (p[i].haslayer(Dot11)):
                        try:
                            type.append(p[i].getlayer(Dot11).type)
                        except AttributeError:
                            type.append("0")
                        try:
                            subtype.append(p[i].getlayer(Dot11).subtype)
                        except AttributeError:
                            subtype.append("0")
                        try:
                            addr1.append(p[i].getlayer(Dot11).addr1)
                        except AttributeError:
                            addr1.append("0")
                        try:
                            addr2.append(p[i].getlayer(Dot11).addr2)
                        except AttributeError:
                            addr2.append("0")
                        try:
                            addr3.append(p[i].getlayer(Dot11).addr3)
                        except AttributeError:
                            addr3.append("0")
                        try:
                            essid.append(p[i].info)
                        except AttributeError:
                            essid.append("0")
        return {'type':type,'subtype':subtype,'addr1':addr1,'addr2':addr2,'addr3':addr3,'essid':essid}


def wildCardAPDetect2(packets):
    ssids = []
    for p in packets:
        if (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)):
            if p.haslayer(Dot11Elt):
                ssids.append(p[Dot11Elt].info)
                if p_ssid in ssids:
                        bssid = str(p.addr3)
			meter(bssid, p_ssid, device)
			return "Karma"
    return "OK"

	
def wildCardAPDetect(packet_info):
        ssids={}
        for i in range(0,len(packet_info['addr2'])):
            bssid=str(packet_info['addr2'][i])
            essid=str(packet_info['essid'][i])
            type=packet_info['type'][i]
            subtype=packet_info['subtype'][i]
            if(subtype==8 or subtype==5):
                if(essid != "0" and essid != ""):
                   ssids.setdefault(bssid, {})[essid] = 1
        for bssid in ssids.keys():
		if( len(ssids[bssid].keys() ) > 1 ):
			essids = ' '.join(ssids[bssid].keys())
			print("ESSID: " + essids) 
			meter(bssid, essids)
			status = "Karma"
			return status
	status = "OK"
	return status

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
    return devices

def get_random_ssid():
    return "Home23123"

def probe_ssid(p_ssid, device):
	pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2="00:11:22:33:44:55",addr3="ff:ff:ff:ff:ff:ff")/Dot11ProbeReq()/Dot11Elt(ID="SSID", info=p_ssid)
        try:
            sendp(pkt,count=10,inter=.1,verbose=3,iface=device)
            print("Probe request sent for: \"" + p_ssid + "\"")
        except:
            raise

if __name__ == "__main__":
	if ( len(sys.argv) > 1 ):
		devices.append(sys.argv[1])
	else:
		devices = enable_mon()
                toggle_devices = itertools.cycle(devices).next
	global statuis
	global detect_led_rate
        p_ssid = get_random_ssid()
	detect_led_rate = 0
        #chans = [1, 6, 11]
        chans = [1]
        n_packets = 2000
        timeout = 5
	led_init()
	while(True):
            for chan in chans:
		#channel_command = "iwconfig " + str(interface) + " channel " + str(c)
		#os.system(channel_command)
                device=toggle_devices()
                probe_ssid(p_ssid,device)
		packets = sniff(iface=devices,count=n_packets,timeout=timeout)
		packet_info = collectInfo(packets)
		status = wildCardAPDetect2(packets)
		flash_status(str(len(packets)), str(chan), str(status))
		print( "Channel: " + str(chan) + ", Packets: " + str(len(packets)) + ", " + str(status))
