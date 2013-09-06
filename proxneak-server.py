# File: proxneak-server.py
# Copyright (c) 2012 by Jarrod Frates
#
# GNU General Public Licence (GPL)
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
#

import argparse
import base64
import bz2
import pickle
import pcapy
import socket
from struct import *
import sys
import time

parser = argparse.ArgumentParser(description='Receive data from any ' +
    'connection that allows traffic to pass through, even if there\'s a ' +
    'regenerative proxy in the stream. Be aware that random latency can ' +
    'cause problems at the receiving end.  Requires root privileges.')
parser.add_argument('-i', nargs=1, metavar='<interface>',
    help='Listener network interface (required)')
parser.add_argument('-s', nargs=1, metavar='<src>',
    help='Sending IP address (optional)')
parser.add_argument('-d', nargs=1, metavar='<dst>',
    help='Receiving IP address (optional)')
parser.add_argument('-p', nargs=1, metavar='<port>',
    help='Listener port (default is 53)')
parser.add_argument('--proto', nargs=1, metavar='<protocol>',
    help='Protocol to use (T=TCP, U=UDP (default), I=ICMP)')
parser.add_argument('-f', nargs=1, metavar='filename',
    help='Output file name (required)')
parser.add_argument('-r', nargs=1, metavar='filename', help='Read a list ' +
    'file in (requires --proto be specified)')
parser.add_argument('-v', action='store_true', help='Verbose mode')
parser.add_argument('-V', action='version', version='0.3',
    help='Display version number')
parser.add_argument('-z', action='store_true',
    help='Incoming content is compressed with bzip2')

args = parser.parse_args()

# Set some default parameters if they're not already set by argument.
# Defaults are port 80, 1 packet/sec, use UDP
if not args.i:
    print 'Requires an interface be specified with -i.  Exiting.'
    sys.exit()
else:
    i_face = args.i[0]

if not args.p:
    dstport = 53
else:
    dstport = int(args.p[0])

if not args.f:
    print 'Requires an output file be specified with -f.  Exiting.'
    sys.exit()
else:
    f_out = args.f[0]

if not args.proto:
    proto = '\\udp'
else:
    if args.proto[0] == 't':
        proto = '\\tcp'
    elif args.proto[0] == 'u':
        proto = '\\udp'
    elif args.proto[0] == 'i':
        proto = '\\icmp'
    else:
        proto = '\\udp'

if args.r:
    if not args.f:
        print 'Requires a protocol be specified with --proto. Exiting.'
        sys.exit()
    else:
        f_in = args.r[0]
else:
    f_in = None


# Create a list to store useful information about the packets received
# Contents will vary based on protocol involved, but will always include time
packets = []
gap = 0
message = ''
filt = 'ip proto ' + proto + ' && port ' + str(dstport)
if args.s:
    filt = filt + ' && ' + args.s
if args.d:
    filt = filt + ' && ' + args.d


def listener():
    # Setup listener using pcapy
    # Listen on i_face, large snaplen, not promiscuous, no timeout
    cap = pcapy.open_live(i_face, 65536, 1, 0)
    cap.setfilter(filt)

    # Start capturing packets to process
    while (1):
        (header, packet) = cap.next()
        packetstore(packet)


# Add packets to the packet store.  Working only for UDP right now.
def packetstore(p):
    global packets
    p_info = parse_packet(p)
    if args.v:
        print p_info[0]
    # TODO: If TCP, check if sequence number is already present and don't
    #       append it if it is.  This will protect against proxies that
    #       continue to try to connect even if the originating system is no
    #       longer trying to send.
    packets.append(p_info)
    if len(packets) == 8:
        synchronize()
    if len(packets) >= 24:
        check_finish()


# Much of the following code copied from Silver Moon
# www.binarytides.com/code-a-packet-sniffer-in-python-with-pcapy-extension/
def parse_packet(packet):
    # Parse the Ethernet header, unpack, and extract the Ethernet proto number.
    eth_len = 14

    eth_header = packet[:eth_len]
    eth = unpack('!6s6sH', eth_header)
    eth_proto = socket.ntohs(eth[2])

    # Parse IP packets (IP Proto number is 8)
    if eth_proto == 8:
        # Parse IP header
        # Take first 20 characters for the IP header
        ip_header = packet[eth_len:20 + eth_len]
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        # Put them into a usable structure
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_len = ihl * 4

        # Start extracting useful information
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        # TCP Protocol
        if protocol == 6:
            t = iph_len + eth_len
            tcp_header = packet[t:t + 20]

            tcph = unpack('!HHLLBBHHH', tcp_header)

            s_port = tcph[0]
            d_port = tcph[1]
            sequence = tcph[2]

            return [time.time(), s_addr, s_port, sequence]

        # UDP Protocol
        elif protocol == 17:
            u = iph_len + eth_len
            udph_len = 8
            udp_header = packet[u:u + 8]

            udph = unpack('!HHHH', udp_header)

            s_port = udph[0]
            d_port = udph[1]

            info = [time.time(), s_addr, s_port]
            return info

        # ICMP Protocol
        elif protocol == 1:
            i = iph_len + eth_len
            icmph_len = 4
            icmp_header = packet[i:i + 4]

            icmph = unpack('!BBH', icmp_header)

            icmp_type = icmph[0]
            icmp_code = icmph[1]

            return [time.time(), s_addr, icmp_type, icmp_code]

        # If not TCP/UDP/ICMP
        else:
            print 'Protocol not TCP/UDP/ICMP. Exiting.'
            sys.exit()


# Use the initial 8 packets to determine average packet spacing.  Failure to
# receive any of these will throw off the entire reception.
def synchronize():
    global gap
    gap = (packets[7][0] - packets[0][0]) / 7
    if args.v:
        print "Average gap: " + str(gap) + " seconds"


# Look at the last 8 packets received and see if they came in within
# approximately the same spacing as the first sequence.  The closing sequence
# is 0x00FF, represented by 8 no-packets and 8 packets.  This is a unique
# sequence given that the message itself is base64-encoded.
def check_finish():
    global packets
    global gap
    q = len(packets) - 1
    gap_check = (packets[q][0] - packets[q - 15][0]) / 15
    # Allow a small fudge factor in the check for random latency
    if gap_check <= gap * 1.10:
        print "Decoding..."
        p_decode(packets)
        reset()


# Turn the packet store into a usable message file
def p_decode(m):
    global message
    global f_out

    # Start with the 8th and 9th packets to determine bit spacing between them.
    # If it's greater than gap, divide and round to determine by how much and
    # add enough zeroes to buffer.
    a = 7
    b = 8
    tempStr = ''
    print 'Packets received: ' + str(len(m))
    while b < (len(m) - 7):
        t = m[b][0] - m[a][0]
        u = round(t / gap)
        # Verbose code
        if args.v:
            print 'Current pair: %.6f and %.6f and Gap = %.2f' % \
            (m[b][0], m[a][0], u)
        tempStr = tempStr + ('0' * (int(u) - 1)) + '1'
        # The following decoder was inspired by code from Lelouch Lamperouge
        # http://stackoverflow.com/questions/7732496/
        if len(tempStr) >= 8:
            x = int(tempStr[0:8], 2)
            message = message + chr(x)
            # Debug code to see what's actually coming in'
            if args.v:
                print 'Character: ' + str(x)
            if len(tempStr) == 8:
                tempStr = ''
            else:
                tempStr = tempStr[8:]
                if tempStr[0] == 1:
                    tempStr = '0' + tempStr
        a += 1
        b += 1
    # Create a file called something like proxneak-1372837358 if no filename
    # has been provided.
    # At the moment, I don't have a way to guess the proper extension
    # TODO: Add some sanity checking to make sure the Base64 message ends in a
    #       valid format.
    if not f_out:
        f_out = 'proxneak-' + str(int(time.mktime(time.gmtime())))
    tempFile = open(f_out, 'wb')
    if args.z:
        tempFile.write(bz2.decompress(base64.b64decode(message)))
    else:
        tempFile.write(base64.b64decode(message))
    tempFile.close()
    print "Message written out to " + f_out

    # Save Base64 to compare input and output or partial recovery in case
    # of corrupted transmission
    tMessageFile = open(f_out + '-message', 'wb')
    tMessageFile.write(message)
    tMessageFile.close

    # Debug code for possible later use
    if args.v:
        tDebugFile = open(f_out + '-debug', 'wb')
        pickle.dump(m, tDebugFile)
        tDebugFile.close

    sys.exit()


def main():
    global packets
    global f_in
    if f_in:
        f = open(f_in, 'r+')
        packets = pickle.load(f)
        f.close
        synchronize()
        p_decode(packets)
    else:
        listener()


if __name__ == '__main__':
    main()
