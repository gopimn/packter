#!/usr/bin/env python2
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
debug=int(args.debugMode)

def printv(string):
    global debug
    if debug == 1:
        print string

#print args.iface
# print args.remoteAddr 
if args.iface == 1:
    gws=net.gateways()
    aux=gws['default'][net.AF_INET]
    iface=str(aux[1])
else:
    iface=args.iface
printv(iface)
net.ifaddresses(iface)
ip = net.ifaddresses(iface)[net.AF_INET][0]['addr']
printv(ip)


##5 min GATTERING CHILD FUNCTION!
def child():
    k=0
    n=0
    c=0
    fileName = time.strftime("%Y%m%d-%H%M%S")
    fileName = './packter'+fileName+'.txt'
    printv(fileName)
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
    f.flush()
    f.close()
    printv ('File: '+ fileName + ' written succesfully')
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
# debug mode, what should be printed and what not
# error if no connection
# say the functionality of the program if errors
# signals to communicate between child and parent
# do you want the no ip packets to be counted on the file
