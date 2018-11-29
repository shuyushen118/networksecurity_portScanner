import getopt, sys
from scapy.all import *
import dpkt, pcap
#import datetime
import time
import sys
from dpkt.compat import compat_ord
from datetime import datetime
#variables to hold values from previous packet
#oldTime = datetime.datetime.now()
oldIP = socket.gethostbyname(socket.gethostname())
def set_OldIP(input):
    global oldIP
    oldIP = input
oldPort = 0
def set_OldPort(input):
    global oldPort
    oldPort = input
count = 0
def add_count():
    global count
    count += 1
#    print ("count is {}").format(count)
def reset_count():
    global count
    count = 0
store_timestamp = "0"
def set_store_timestamp(input):
    global store_timestamp
    store_timestamp = input
def  time_difference(t1,t2):
    fmt = '%Y-%m-%d %H:%M:%S.%f'
    tstamp1 = datetime.strptime(t1, fmt)
    tstamp2 = datetime.strptime(t2, fmt)
    
    if tstamp1 > tstamp2:
        td = tstamp1 - tstamp2
    else:
        td = tstamp2 - tstamp1
        td_mins = int(round(td.total_seconds() / 60))

    print('The difference is approx. %s minutes' % td_mins)
    return td_mins

#oldIP  = socket.gethostbyname(socket.gethostname())
#oldPort =

def mac_addr(address):
    """Convert a MAC address to a readable/printable string
        Args:
        address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
        Returns:
        str: Printable/readable MAC address
        """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
        inet (inet struct): inet network address
        Returns:
        str: Printable/readable IP address
        """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def usage():
    print >>sys.stderr, 'usage: %s [-i device] [pattern]' % sys.argv[0]
    sys.exit(1)

def main():
    sys.stdout = open("PSDector.txt","w")
    opts, args = getopt.getopt(sys.argv[1:], 'i:h')
    name = None
    for o, a in opts:
        if o == '-i': name = a
        else: usage()
    #    time_out = time.time () + 5*60
    #    while time.time() < time_out:
    pc = pcap.pcap(name)
    pc.setfilter(' '.join(args))
    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
            pcap.DLT_NULL:dpkt.loopback.Loopback,
            pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]
#    time_out = time.time() + 5*60
    try:
#        print 'listening on %s: %s' % (pc.name, pc.filter)

        for timestamp, buf in pc:
            # timestamp in IP
            IP_timestamp = str(datetime.utcfromtimestamp(timestamp))
#            print IP_timestamp
            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(buf)
    #            print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

            # Make sure the Ethernet frame contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
#                print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
                continue

            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            ip = eth.data
            #ignore IGMP packet
            if isinstance(ip.data, dpkt.igmp.IGMP):
    #                print ("caught IGMP")
                continue
            #ignore ICMP packet
            if isinstance(ip.data, dpkt.icmp.ICMP):
    #                print ("caught ICMP")
                continue
            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = (ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
            #compare IP address if same look at the port it is  talking
            if(inet_to_str(ip.src) == oldIP):
    #                print ("same IP address")
                #compare this port destination with last port
                desPort = ip.data.dport
                if (desPort == oldPort +1) :
                    add_count()
                #update old port to present port
                set_OldPort(desPort)
            #if IP address are different update old IP address to new IP address
            else:
                #reset count to zero
                reset_count()
                #reset time window
                set_store_timestamp(IP_timestamp)
                #set old IP address
                set_OldIP(inet_to_str(ip.src))
    #                print ("old ip now is {}").format(oldIP)
    #                set old port
                set_OldPort(ip.data.dport)
            if (count >= 15 and time_difference (store_timestamp,IP_timestamp) <= 5) :
                print ("port scan detected at {0}").format(inet_to_str(ip.src))
               

    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print '\n%d packets received by filter' % nrecv
        print '%d packets dropped by kernel' % ndrop

if __name__ == '__main__':
    time_out = time.time () + 5*60
#    while time.time() < time_out:
    main()
