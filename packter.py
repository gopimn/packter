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
parser.add_argument('-v', action = 'store_const', dest = 'verboseMode', const =1,
                   help='Show extra information with value 1')
parser.add_argument('-t', action = 'store', dest = 'timeSecs', default = 300,
                   help='Duration of the files')
parser.add_argument('-f', action = 'store_const', dest = 'header', const = 1,
                   help='Indicates either to write the header/footer of the file or not')
parser.add_argument('-d', action = 'store_const', dest = 'detailed', const = 1,
                   help='Save detailed information file')

#########################Functions###################
def printv(string):
    global debug
    if debug == 1:
        print string

###############           WELCOME           ###############

args = parser.parse_args()
captureTimeSecs=int(args.timeSecs)
debug=args.verboseMode
remotead=args.remoteAddr
header=args.header
detailed=args.detailed

print '\nWelcome to packter :)\n'
if debug != 1:
    print 'Silent mode activated, will do the work BUT will not print anything '
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
totalupCount=0
totalupBytes=0
totaldownCount=0
totaldownBytes=0
secCounter=0
upBytes=0
downBytes=0
upCount=0
downCount=0
actualSec=0
fileName = time.strftime("%Y%m%d-%H%M%S")
fileName = 'packter'+fileName+'.txt'
f = open(fileName, 'w')
if detailed == 1:
    fileName2 =  'packterDetailed'+ time.strftime("%Y%m%d-%H%M%S")+'.txt'
    f2=  open(fileName2, 'w')
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
printv('\nCapture has started, do not disconnect your network interface\n')
capture = pyshark.LiveCapture(interface=iface)
capture.sniff(timeout= (captureTimeSecs+1)) #one more sec just in case
printv('Finished capture, processing data and saving results\n')
for i in range(0,len(capture)):
    if 'IP' in capture[i]:
        if  capture[i].ip.src == ip or capture[i].ip.dst == ip:
            if args.remoteAddr != 1:
                if (capture[i].ip.src == args.remoteAddr or capture[i].ip.dst == args.remoteAddr):
                    if detailed == 1:
                        info2=str(actualSec.strftime("%H:%M:%S"))+':'+ capture[i].ip.src+' -> '
                        info2=info+capture[i].ip.dst+ ' size: '+capture[i].length+' Bytes\n'
                        f2.write(info2)
                    if actualSec == 0:
                        actualSec=capture[i].sniff_time
                    if actualSec.second != capture[i].sniff_time.second:
                        info=str(actualSec.strftime("%H:%M:%S"))+'\t'+str(upCount)+'\t'+str(upBytes)+'\t'+str(downCount)+'\t'+str(downBytes)+'\n'
                        f.write(info)
                        printv(info)
                        actualSec=capture[i].sniff_time
                        upBytes=0
                        downBytes=0
                        upCount=0
                        downCount=0
                    if  capture[i].ip.src == ip:#
                        upBytes = upBytes + int(capture[i].length)
                        upCount = upCount + 1
                        totalupBytes=totalupBytes+ + int(capture[i].length)
                        totalupCount=totalupCount+1
                    else:
                        downBytes = upBytes + int(capture[i].length)
                        downCount = upCount + 1
                        totaldownBytes=totaldownBytes+ + int(capture[i].length)
                        totaldownCount=totaldownCount+1
            else:
                if actualSec == 0:
                    actualSec=capture[i].sniff_time
                if detailed == 1:
                    info2=str(actualSec.strftime("%H:%M:%S"))+':'+ capture[i].ip.src+' -> '
                    info2=info2+capture[i].ip.dst+ ' size: '+capture[i].length+' Bytes\n'
                    f2.write(info2)
                if actualSec.second != capture[i].sniff_time.second:
                    info=str(actualSec.strftime("%H:%M:%S"))+'\t'+str(upCount)+'\t'+str(upBytes)+'\t'+str(downCount)+'\t'+str(downBytes)+'\n'
                    f.write(info)
                    printv(info)
                    actualSec=capture[i].sniff_time
                    upBytes=0
                    downBytes=0
                    upCount=0
                    downCount=0
                if  capture[i].ip.src == ip:#
                    upBytes = upBytes + int(capture[i].length)
                    upCount = upCount + 1
                    totalupBytes=totalupBytes+ + int(capture[i].length)
                    totalupCount=totalupCount+1
                else:
                    downBytes = upBytes + int(capture[i].length)
                    downCount = upCount + 1
                    totaldownBytes=totaldownBytes+ + int(capture[i].length)
                    totaldownCount=totaldownCount+1
    else:
        totalNoip=totalNoip+1
        printv( 'NO IP:'+str(totalNoip))
if header == 1:
    info='########################################################################\n'
    info = info + 'Total packets uploaded: ' + str(totalupCount) + '\nTotal bytes uploaded: ' + str(totalupBytes)+'\n'
    info = info + 'Total packets downloaded: ' + str(totaldownCount) + '\nTotal bytes downloaded: ' + str(totaldownBytes)+'\n'
    info = info + 'Total packets: ' + str(totaldownCount + totalupCount) + '\nTotal bytes: ' + str(totaldownBytes+ totalupBytes)+'\n'
    info = info +'Total no IP: ' + str(totalNoip)+'\n'
    printv (info)
    f.write(info)
if detailed == 1:
    f2.close()
    printv('File '+ fileName2 + ' written succesfully')
f.flush()
f.close()
printv('File '+ fileName + ' written succesfully')
print 'Program ended correctly\nGood bye.'
