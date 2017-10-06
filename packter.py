g#!/usr/bin/env python2

import argparse
import pyshark
import time, datetime, time
import netifaces as net
import sys, os
parser = argparse.ArgumentParser(description='Argument parser of the packet counter script')
parser.add_argument('-i',action = 'store', dest = 'iface', default=1,
                   help='Network interface  to be sniffed')
parser.add_argument('-a', action = 'store', dest = 'remoteAddr', default = 1,
                   help='Remote address')
parser.add_argument('-d', action = 'store', dest = 'debugMode', default = 0,
                   help='Remote address')
parser.add_argument('-t', action = 'store', dest = 'timeSecs', default = 300,
                   help='Remote address')
args = parser.parse_args()
captureTimeSecs=int(args.timeSecs)
#print args.iface
# print args.remoteAddr 
if args.iface == 1:
    gws=net.gateways()
    aux=gws['default'][net.AF_INET]
    iface=str(aux[1])
else:
    iface=args.iface
print iface
net.ifaddresses(iface)
ip = net.ifaddresses(iface)[net.AF_INET][0]['addr']
print ip


##5 min GATTERING CHILD FUNCTION!
def child():
    k=0
    n=0
    fileName = time.strftime("%Y%m%d-%H%M%S")
    fileName = './packter'+fileName+'.txt'
    print fileName
    f = open(fileName, 'w')
    #start_time = time.time()
    capture = pyshark.LiveCapture(interface=iface)
    capture.sniff(timeout= captureTimeSecs)
    for i in range(0,len(capture)):
        if 'IP' in capture[i]:
            if  capture[i].ip.src == ip or capture[i].ip.dst == ip:
                if args.remoteAddr != 1:
                    if (capture[i].ip.src == args.remoteAddr or capture[i].ip.dst == args.remoteAddr):
                        hagale= datetime.datetime.now()
                        info=str(hagale)+':'+ capture[i].ip.src+' -> '+capture[i].ip.dst+ ' size: '+capture[i].length+' Bytes\n'
                        print info
                        f.write(info)
                        k=k+1
                else:
                    hagale= datetime.datetime.now()
                    info=str(hagale)+':'+ capture[i].ip.src+' -> '+capture[i].ip.dst+ ' size: '+capture[i].length+' Bytes\n'
                    print info
                    f.write(info)
                    k=k+1
        else:
            n=n+1
            print 'NO IP:',n
    f.flush()
    f.close()
    print 'File: '+ fileName + ' written succesfully'
    os._exit(0)
    
def parent():
    while True:
        print "We are in the parent process with PID= %d"%os.getpid()
        newRef=os.fork()
        if newRef==0:
            child()
        else:
            print "We are in the parent process and our child process has PID= %d\n"%newRef
        time.sleep(captureTimeSecs)

parent()

#TODO
# debug mode
# error if no connection
# print at the end of the file the amount of packets, and the amount of bytes sended on the time interval
# say the functionality of the program
# signals to ocmmunicate between child and parent
