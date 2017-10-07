#!/usr/bin/env python2
import argparse
import pyshark
import time, datetime, time
import netifaces as net
import sys, os

parser = argparse.ArgumentParser(description='Python packet counter script')
parser.add_argument('-i',action = 'store', dest = 'iface', default=1,
                   help='Network interface  to be sniffed')
parser.add_argument('-a', action = 'store', dest = 'remoteAddr', default = 1,
                   help='Remote address')
parser.add_argument('-v', action = 'store', dest = 'verboseMode', default = 0,
                   help='Show extra information with value 1')
parser.add_argument('-t', action = 'store', dest = 'timeSecs', default = 300,
                   help='Duration of the files')


###############           WELCOME           ###############
print '\n###########  Welcome to packter ###########\n'

args = parser.parse_args()
captureTimeSecs=int(args.timeSecs)
debug=int(args.verboseMode)
remotead=args.remoteAddr
gws=net.gateways()
if gws['default'] == {}:
    print 'No connection'
    exit(0)
aux=gws['default'][net.AF_INET]

if args.iface == 1:
    iface=str(aux[1])
else:
    iface=args.iface

net.ifaddresses(iface)
ip = net.ifaddresses(iface)[net.AF_INET][0]['addr']
    
print 'The interface to capture is: '+iface
print 'The local ip is: '+ip
if remotead != 1:
    print 'The remote ip is: '+remotead
if debug == 0:
    print 'No package prints configuration'
else:
    print 'Will print all the packets'
print 'Will save the files every '+str(captureTimeSecs)+' seconds'
print 'starting in\n3'
time.sleep(1)
print '2'
time.sleep(1)
print '1'
time.sleep(1)
print 'GO!'
time.sleep(1)
##5 min GATTERING CHILD FUNCTION!

def printv(string):
    global debug
    if debug == 1:
        print string
        
def child():
    k=0
    n=0
    c=0
    fileName = time.strftime("%Y%m%d-%H%M%S")
    fileName = './packter'+fileName+'.txt'
    print 'The actual file is: '+fileName
    f = open(fileName, 'w')
    info = '####################### Packter File #########################'
    f.write(info)
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
                        printv(info)
                        f.write(info)
                        c= c+int (capture[i].length)
                        k=k+1
                else:
                    hagale= datetime.datetime.now()
                    info=str(hagale)+':'+ capture[i].ip.src+' -> '+capture[i].ip.dst+ ' size: '+capture[i].length+' Bytes\n'
                    printv (info)
                    f.write(info)
                    c= c+int (capture[i].length)
                    k=k+1
        else:
            n=n+1
            printv( 'NO IP:'+str(n))
    info='#########################################################################\n'
    info = info + 'total packets on interval: ' + str(k) + '\n Total bytes on interval:' + str(c)
    printv (info)
    f.write(info)
    f.flush()
    f.close()
    print 'File: '+ fileName + ' written succesfully'
    os._exit(0)
    
def parent():
    while True:
        printv("We are in the parent process with PID= %d"%os.getpid())
        newRef=os.fork()
        if newRef==0:
            child()
        else:
            printv("We are in the parent process and our child process has PID= %d\n"%newRef)
        time.sleep(captureTimeSecs)

parent()

#TODO
# signals to communicate between child and parent
