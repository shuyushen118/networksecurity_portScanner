import socket
#import subprocess
import sys
from datetime import datetime

def getservicename(port):
    try:
        name = socket.getservbyport(port)
    except:
        return "NA"
    return name

def portscan(input):
 
    localhost    = input
    localhostIP  = socket.gethostbyname('localhost')
    IP_tuple = tuple([localhostIP])

    # Print a nice banner with information on which host we are about to scan
#    print "-" * 60
#    print "Please wait, scanning host", localhostIP
#    print "-" * 60

    # Check what time the scan started
    t1 = datetime.now()
    
    #keep count for the ports scanned
    count = 0
    sys.stdout = open("scanner.txt","w")

    try:
        
        for port in range(0,65535):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((localhostIP, port))
            if result == 0:
                count +=1
                #save output to a file
#                sys.stdout = open("scanner.txt","w")
                print "{} ({}) was open".format(port, getservicename(port))
#                print getservicename(port)
            s.close()
#            sys.stdout.close()

    except KeyboardInterrupt:
#        print "End program"
        sys.exit()


    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1
    days, seconds = total.days,total.seconds
    hours = days * 24 + seconds
    minute = (seconds % 3600)
    seconds = seconds % 60
    total = hours + minute + seconds

#    total_s = total.hour * 3600 + total.minute * 60 +t.second
    #split time
#    (h,m,s) = total.split(':')

    #time per port
    timePerport = total/count
    print count

    # Printing the information to screen
    print "time elapsed = {}s" .format(total)
    print "time per scan = {}s".format(timePerport)
    sys.stdout.close()

#main
hostname = sys.argv[1]
portscan(hostname)
