#!/usr/bin/python3
##
## Authors: Philip Bertuglia 
## Last Update:    March 14, 2021
##

import sys, re, time
import netifaces
import RPi.GPIO as GPIO
import itertools
import queue
import random
import string
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
#chans=['1','6','11','14']
#chans=['36','38','40','42','44','46','48','149','151','153','155','157','159','161','165']
chans=['1','6','11','14','36','38','40','42','44','46','48','149','151','153','155','157','159','161','165']
#chans=['1','11','38']

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

## Ephemral Karma SSIDs.
karma_ssid_list = []

## Static allow and block lists.
a_ssid_list = [
        'Sonos_YMKD5ESmQ9GLsXch3MeYDv5bj7'
        ]

b_ssid_list = [
        ]

wtf_ssid_list = [
        ]

a_macf_list = [
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
    channel = 0
#    q.put_nowait("Frame Received. \n")
#    if p.haslayer(Dot11EltDSSSet):
#        channel = p[Dot11EltDSSSet].channel.decode('utf-8') 
#        print(channel)
    if p.haslayer(Dot11ProbeReq) and p.haslayer(Dot11Elt):
            bssid = str(p.addr2)
            try:
                ssid = p[Dot11Elt].info.decode('utf-8')
            except:
                ssid = p[Dot11Elt].info.decode('utf-16')
            try:
                maco = EUI(bssid)
                macf = maco.oui.registration().org
            except:
                pass
            if ssid in karma_ssid_list:
                seq = [4,0]
                t = 0.25
                count = 0
                alert = "Sniffed our own Karma test probe. Not evil."
                q.put_nowait("Self-sniffed Karma Probe: " + ssid + "\n")
            elif ssid != "":
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
                elif (ssid not in a_ssid_list) and (ssid not in karma_ssid_list):
                    seq = [4,0]
                    t = 0.2
                    count = 5
                    alert = "Unknown_SSID_Probe"
                else:
                    q.put_nowait("Probe Received:" + ssid + " \n")
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
#                if macf not in a_macf_list:
#                    seq = [6,0]
#                    t = 0.25
#                    count = 10
#                    alert = "Unknow_HW_Probe"
    elif (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and p.haslayer(Dot11Elt):
            bssid = str(p.addr2)
            try:
                ssid = p[Dot11Elt].info.decode('utf-8')
            except:
                ssid = p[Dot11Elt].info.decode('utf-16')
            if ssid in karma_ssid_list:
                seq = [1,2,4,2,1,2]
                t = 0.25
                count = 30
                alert = "Karma_Attack_Detected!"
                q.put_nowait("Karma: " + ssid + "\n")
#            else:
#                q.put_nowait("Beacon Received:" + ssid + " \n")
    if count != 0:
        args = [seq,t,count]
        blink_thread(args)
        log_string = alert + ";" + str(ptime) + ";" + bssid + ";" + str(macf) + ";" + ssid + "\n"
        q.put_nowait(log_string)
        lf.write(log_string)
        lf.flush()

def start_channel_thread(a_devices, g_devices, sniff_devices):
    global threads
    args=[a_devices, g_devices, sniff_devices]
    threads['channel'] = Thread(target=rotate_chans, args=[args,])
    threads['channel'].daemon = True
    threads['channel'].start()

def rotate_chans(args):
    a_devices = args[0]
    g_devices = args[1]
    sniff_devices = args[2]
    q.put_nowait("a_devices: " + str(a_devices) + "\ng_devices: " + str(g_devices) + "\nsniff_devices: " + str(sniff_devices) + "\n")
    if len(sniff_devices) > 0:
        sniff_toggle = itertools.cycle(sniff_devices)
    while True:
        for chan in chans:
            device = next(sniff_toggle)
            if int(chan) > 15: 
                if len(a_devices) > 0:
                   while (device not in a_devices): device = next(sniff_toggle)
                else:
                   continue
            run(['/sbin/iwconfig', device, 'channel', chan])
#            q.put_nowait(device + " set to channel " + chan + "." + "\n")
            time.sleep(1)

def header():
    start_time=time.strftime("%Y-%m-%d %H:%M:%S %Z")
    header_line = "Type;Date(" + start_time + ");BSSID;Manufacturer;SSID" + "\n"
    lf.write(header_line)
    q.put_nowait(header_line)
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
    q.put_nowait("sniffing on: " + device + "\n")
    sniff(iface=device, prn=phandle, store=0)

def enable_mon():
    devices = []
    g_devices = []
    a_devices = []
    a_chan = "42"
    g_chan = "11"
#    p00 = run(['/usr/sbin/airmon-ng', 'check', 'kill'])
    for iface in netifaces.interfaces():
        if "wlan" in iface:
            devices.append(iface)
    for device in devices:
#        print(device)
        p0 = run(['/sbin/ifconfig', device, 'down'])
        p1 = run(['/sbin/iwconfig', device, 'mode', 'monitor'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "Operation not supported" in p1.stderr.decode('utf-8'):
            continue
        else:
            p2 = run(['/sbin/ifconfig', device, 'up'])
            p3 = run(['/sbin/iwconfig', device, 'channel', a_chan], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if "Invalid argument" in p3.stderr.decode('utf-8'):
                g_devices.append(device)
                p4 = run(['/sbin/iwconfig', device, 'channel', g_chan], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                a_devices.append(device)
    if len(devices) == 0:
        print("No usable interface found.")
        sys.exit()
    return (g_devices,a_devices)

def start_karma_probe_thread(device):
    global threads
    args=[device]
    threads['probe'] = Thread(target=send_probes, args=[args,])
    threads['probe'].daemon = True
    threads['probe'].start()

def send_probes(args):
    device = args[0]
    probe_ssid = get_random_ssid()
    karma_ssid_list.append(probe_ssid)
    print("Karma Probe ESSID: " + probe_ssid)
    print("Karma Probe Device: " + probe_device)
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
        t = 150
        while t:
            t -= 1
            try:
                sendp(pkt, count=5, inter=0.1, iface=device, verbose=0)
            except:
                raise
            time.sleep(30)
        probe_ssid = get_random_ssid()
        karma_ssid_list.append(probe_ssid)
        print("Karma Probe ESSID: " + probe_ssid)
        essid = Dot11Elt(ID='SSID',info=probe_ssid)
        pkt = RadioTap(present=0)\
           /Dot11(type=0,subtype=4,FCfield=0,addr1=addr1,addr2=addr2,addr3=addr3)\
           /param/essid/rates

def get_random_ssid():
    letters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(letters) for i in range(10))
    return random_string

if __name__ == "__main__":
    try:
        lf=open(logfile,'a')
    except:
        print("Log file not open.")
        sys.exit()
    all_off()
    (g_devices, a_devices) = enable_mon()
    sniff_devices = a_devices + g_devices
    if (len(g_devices) + len(a_devices)) < 2:
        print("You need at least two WiFi devices that support monitor and frame injection.")
        sys.exit()
    if len(g_devices) > 0:
        probe_device = g_devices[0]
    else:
        probe_device = a_devices[0]
    sniff_devices.remove(probe_device)
    probe_thread = start_karma_probe_thread(probe_device)
    start_channel_thread(a_devices, g_devices, sniff_devices)
    start_sniff_threads(sniff_devices)
    header()
    while True:
        while not q.empty():
            output = q.get()
            print(output, end='')
        time.sleep(0.5)
    lf.close()
