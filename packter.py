#!/usr/bin/env python2
import argparse
import pyshark
import time, datetime
import netifaces as net
import sys, os, signal

parser = argparse.ArgumentParser(description='Python packet counter script using pyshark libraries')
parser.add_argument('-i',action = 'store', dest = 'iface', default=1,
                   help='Network interface  to be sniffed')
parser.add_argument('-a', action = 'store', dest = 'remoteAddr', default = 1,
                   help='Remote address')
parser.add_argument('-v', action = 'store', dest = 'verboseMode', default = 0,
                   help='Show extra information with value 1')
parser.add_argument('-t', action = 'store', dest = 'timeSecs', default = 300,
                   help='Duration of the files')
parser.add_argument('-r', action = 'store', dest = 'header', default = 1,
                   help='Indicates either to write the header/footer of the file or not')
#########################Functions###################
def printv(string):
    global debug
    if debug == 1:
        print string

###############           WELCOME           ###############
print '\n#########################Welcome to Packter#############################\n'
print 'Starting in\n3'
time.sleep(1)
print '2'
time.sleep(1)
print '1'
time.sleep(1)
args = parser.parse_args()
captureTimeSecs=int(args.timeSecs)
debug=int(args.verboseMode)
remotead=args.remoteAddr
header=args.header
gws=net.gateways()
if gws['default'] == {}:
    print 'No connection. End of Program'
    exit(0)
aux=gws['default'][net.AF_INET]
if args.iface == 1:
    iface=str(aux[1])
else:
    iface=args.iface
net.ifaddresses(iface)
ip = net.ifaddresses(iface)[net.AF_INET][0]['addr']
totalNoip=0
totalCount=0
totalBytes=0
secCounter=0
upBytes=0
downBytes=0
upCount=0
downCount=0
actualSec=0
fileName = time.strftime("%Y%m%d-%H%M%S")
fileName = 'packter'+fileName+'.txt'
f = open(fileName, 'w')
if header == 1:
    info = '############################## Packter #################################\n'
    info = info+'The interface to capture is: '+iface + '\n'
    info = info+ 'The local ip is: '+ip+ '\n'
    info = info+'The file name is: '+fileName+'\n'
    f.write(info)
    printv(info)
    if remotead != 1:
        info = 'The remote ip is: '+remotead+ '\n'
        f.write(info)
        printv(info)
    info ='Will save '+str(captureTimeSecs)+' seconds of data'+'\n'
    info=info+'Columns are:timeStamp,upCount,upBytes,downCount,downBytes\n'
    info = info+'############################ Packter Data ##############################\n'
    f.write(info)
    printv(info)
capture = pyshark.LiveCapture(interface=iface)
capture.sniff(timeout= (captureTimeSecs+1)) #one more sec just in case
printv('Finished capture, processing data and saving results')
for i in range(0,len(capture)):
    if 'IP' in capture[i]:
        if  capture[i].ip.src == ip or capture[i].ip.dst == ip:
            if args.remoteAddr != 1:
                if (capture[i].ip.src == args.remoteAddr or capture[i].ip.dst == args.remoteAddr):
                    print 's' #some some
            else:
                totalCount=totalCount+1
                totalBytes=totalBytes + int(capture[i].length)
                if actualSec == 0:
                    actualSec=capture[i].sniff_time
                if actualSec.second != capture[i].sniff_time.second:
                    actualText=str(actualSec.strftime("%H:%M:%S"))+','+str(upCount)+','+str(upBytes)+','+str(downCount)+','+str(downBytes)+'\n'
                    f.write(actualText)
                    printv(actualText)
                    actualSec=capture[i].sniff_time
                    upBytes=0
                    downBytes=0
                    upCount=0
                    downCount=0
                if  capture[i].ip.src == ip:#
                    upBytes = upBytes + int(capture[i].length)
                    upCount = upCount + 1
                else:
                    downBytes = upBytes + int(capture[i].length)
                    downCount = upCount + 1
    else:
        totalNoip=totalNoip+1
        printv( 'NO IP:'+str(totalNoip))
if header == 1:
    info='########################################################################\n'
    info = info + 'Total packets on upload: ' + str(totalCount) + '\nTotal bytes:' + str(totalBytes)+ '\nTotal no IP:' + str(totalNoip)+'\n'
    printv (info)
    f.write(info)
f.flush()
f.close()
printv('File: '+ fileName + ' written succesfully')
