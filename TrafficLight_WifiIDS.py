#!/usr/bin/python3
##
## Authors: Philip Bertuglia 
## Date:    March 14, 2020
##

import sys, re, time
import netifaces
import RPi.GPIO as GPIO
import netifaces
import itertools
import queue
from scapy.all import *
from threading import Thread
from subprocess import run, PIPE
from netaddr import EUI
from itertools import cycle


## Global Vars
logfile="/var/log/probe_log"
q = queue.Queue()
threads = {}
seq_lock = False
#chans=['1','3','6','9','11','12','14']
chans = ['1','6','9','11',]

## TrafficLight Pins, BCM
red = 26
amber = 21
green = 20
seq_lock = False
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(red,GPIO.OUT)
GPIO.setup(amber,GPIO.OUT)
GPIO.setup(green,GPIO.OUT)

## Ephemral Karma SSIDs
karma_ssid_list = []

## Static White and Black Lists
w_ssid_list = [
        'AAOOJVWKS_5GHz',
        'AAOOJVWEW_2Gz',
        'not-free',
        'CSN',
        'hospinet'
        ]

b_ssid_list = [
        'Paracelsus'
        ]

wtf_ssid_list = [
        'TMobileWingman'
        ]

w_macf_list = [
        'AzureWave Technology Inc.',
        'Apple, Inc.',
        ]

def all_off():
    GPIO.output(red,GPIO.HIGH)
    GPIO.output(amber,GPIO.HIGH)
    GPIO.output(green,GPIO.HIGH)

def blink_thread(args):
    thread = Thread(target=blink, args=[args,])
    thread.daemon = True
    thread.start()

def blink(args):
    seq = args[0]
    t = args[1]
    count = args[2]
    global seq_lock
    if seq_lock:
        return
    else:
       seq_lock = True
    for x in range(0,count):
        for c in seq:
            if c & 1:
                GPIO.output(red,GPIO.LOW)
            else:
                GPIO.output(red,GPIO.HIGH)
            if c & 2:
                GPIO.output(amber,GPIO.LOW)
            else:
                GPIO.output(amber,GPIO.HIGH)
            if c & 4:
                GPIO.output(green,GPIO.LOW)
            else:
                GPIO.output(green,GPIO.HIGH)
            time.sleep(t)
    all_off()
    seq_lock = False

def phandle(p):
    ptime=time.strftime("%Y-%m-%d %H:%M:%S %Z")
    alert = ""
    ssid = ""
    macf = ""
    has_apple = False
    has_broadcom = False
    count = 0
    if p.haslayer(Dot11ProbeReq) and p.haslayer(Dot11Elt):
            bssid = str(p.addr2)
            ssid = p[Dot11Elt].info.decode('utf-8')
            try:
                maco = EUI(bssid)
                macf = maco.oui.registration().org
            except:
                pass
            if ssid != "":
                if ssid in wtf_ssid_list:
                    seq = [2,4]
                    t = 0.25
                    count = 10
                    alert = "Untrusted_SSID_Probe"
                elif ssid in b_ssid_list:
                    seq = [1,0]
                    t = 0.5
                    count = 30
                    alert = "Black_Listed_Probe"
                elif (ssid not in w_ssid_list) and (ssid not in karma_ssid_list):
                    seq = [2,0]
                    t = 0.5
                    count = 10
                    alert = "Unknown_SSID_Probe"
            ## iOS randomizes WiFi MACs. Just skip them for now.
            elt = p.getlayer(Dot11Elt)
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
#            elif macf != "":
#                if macf not in w_macf_list:
#                    seq = [6,0]
#                    t = 0.25
#                    count = 10
#                    alert = "Unknow_HW_Probe"
    elif (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and p.haslayer(Dot11Elt):
            bssid = str(p.addr2)
            ssid = p[Dot11Elt].info.decode('utf-8')
            if ssid in karma_ssid_list:
                seq = [1,2,4,2,1,2]
                t = 0.25
                count = 30
                alert = "Karma_Attack_Detected"
#                q.put("Karma: " + ssid + "\n")
    if count != 0:
        args = [seq,t,count]
        blink_thread(args)
        log_string = alert + ";" + str(ptime) + ";" + bssid + ";" + str(macf) + ";" + ssid + "\n"
        q.put(log_string)
        lf.write(log_string)
        lf.flush()

def start_channel_thread(devices):
    global threads
    args=[devices,]
    threads['channel'] = Thread(target=rotate_chans, args=[args,])
    threads['channel'].daemon = True
    threads['channel'].start()

def rotate_chans(args):
    devices = args[0]
    device = devices[0]
    device_len = len(devices)
    if device_len > 1:
        toggle = itertools.cycle(devices)
    elif device == "mon0":
            return
    while True:
        for chan in chans:
            if device_len > 1:
                device = next(toggle)
            if device == "mon0":
                continue
            run(['/sbin/iwconfig', device, 'channel', chan])
            #q.put(device + " set to channel " + chan + "." + "\n")
            time.sleep(0.5)

def header():
    start_time=time.strftime("%Y-%m-%d %H:%M:%S %Z")
    header_line = "Type;Date(" + start_time + ");BSSID;Manufacturer;SSID" + "\n"
    lf.write(header_line)
    q.put(header_line)
    lf.flush()

def start_sniff_threads(devices):
    global threads
    for device in devices:
        args=[device,]
        threads[device] = Thread(target=sniff_thread, args=[args,])
        threads[device].daemon = True
        threads[device].start()

def sniff_thread(args):
    device = args[0]
    q.put("sniffing on: " + device + "\n")
    sniff(iface=device, prn=phandle, store=0)

def enable_mon():
    devices = []
    mon_devices = []
    for iface in netifaces.interfaces():
        if "wlan" in iface:
              devices.append(iface)
    for device in devices:
        print(device)
        p1 = run(['/sbin/iwconfig', device, 'mode', 'monitor'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "Operation not supported" in p1.stderr.decode('utf-8'):
            continue
        else:
            mon_devices.append(device)
            p2 = run(['/sbin/ifconfig', device, 'up'])
    if len(devices) == 0:
        print("No usable interface found.")
        sys.exit()
    return mon_devices

def start_karma_probe_thread(devices):
    global threads
    device = devices[0]
    probe_ssid = get_random_ssid()
    karma_ssid_list.append(probe_ssid)
    args=[device, probe_ssid]
    threads['probe'] = Thread(target=send_probes, args=[args,])
    threads['probe'].daemon = True
    threads['probe'].start()
    return {'probe_device':device, 'probe_ssid':probe_ssid}

def send_probes(args):
    device = args[0]
    probe_ssid = args[1]
    addr1="ff:ff:ff:ff:ff:ff"
    addr2="FA:CE:01:23:45:67"
    addr3="ff:ff:ff:ff:ff:ff"
    param = Dot11ProbeReq()
    essid = Dot11Elt(ID='SSID',info=probe_ssid)
    rates  = Dot11Elt(ID='Rates',info="\x03\x12\x96\x18\x24\x30\x48\x60")
    pkt = RadioTap(present=0)\
        /Dot11(type=0,subtype=4,FCfield=0,addr1=addr1,addr2=addr2,addr3=addr3)\
        /param/essid/rates
    while True:
        try:
            sendp(pkt, count=5, inter=0.1, iface=device, verbose=0)
        except:
            raise
        time.sleep(30)

def get_random_ssid():
    return "Home23123"

if __name__ == "__main__":
    try:
        lf=open(logfile,'a')
    except:
        print("Log file not open.")
        sys.exit()
    all_off()
    devices = enable_mon()
    if len(devices) < 2:
        print("You need at least two (2) WiFi devices that support monitor and inject.")
        sys.exit()
    probe_thread = start_karma_probe_thread(devices)
    probe_ssid = probe_thread['probe_ssid']
    probe_device = probe_thread['probe_device']
    sniff_devices = []
    for device in devices:
        if device != probe_device:
            sniff_devices.append(device) 
    print("Karma Probe Device: " + probe_device)
    print("Sniff Device(s): ", end = '') 
    print(sniff_devices)

    start_channel_thread(devices)
    start_sniff_threads(sniff_devices)
    header()
    while True:
        while not q.empty():
            output = q.get()
            print(output, end='')
        time.sleep(0.5)
    lf.close()
