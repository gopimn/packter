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
capture = pyshark.LiveCapture(interface=iface)
capture.sniff(timeout= (captureTimeSecs+1)) #one more sec just in case
printv('Finished capture, processing data and saving results')
for i in range(0,len(capture)):
    if 'IP' in capture[i]:
        if  capture[i].ip.src == ip or capture[i].ip.dst == ip:
            if args.remoteAddr != 1:
                if (capture[i].ip.src == args.remoteAddr or capture[i].ip.dst == args.remoteAddr):
                    if detailed == 1:
                        info2=str(actualSec.strftime("%H:%M:%S"))+':'+ capture[i].ip.src+' -> '
                        info2=info+capture[i].ip.dst+ ' size: '+capture[i].length+' Bytes\n'
                        f2.write(info2)
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
                if detailed == 1:
                    info2=str(actualSec.strftime("%H:%M:%S"))+':'+ capture[i].ip.src+' -> '
                    info2=info+capture[i].ip.dst+ ' size: '+capture[i].length+' Bytes\n'
                    f2.write(info2)
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
