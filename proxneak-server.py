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
import time
import struct
from scapy.all import *


parser = argparse.ArgumentParser(description='Receive data from any ' +
    'connection that allows traffic to pass through, even if it\'s a ' +
    'regenerative proxy. Be aware that random latency can cause problems ' +
    'at the receiving end.  Requires root privileges.  Server portion ' +
    'requires scapy.')
parser.add_argument('-i', nargs=1, metavar='<interface>',
    help='Listener network interface (not currently implemented)')
parser.add_argument('-l', nargs=1, metavar='<src>',
    help='Listen for IP address (not currently implemented)')
parser.add_argument('-p', nargs=1, metavar='port',
    help='Listener port (default is 53)')
parser.add_argument('--proto', nargs=1, metavar='',
    help='Protocol to use (T=TCP, U=UDP (default), I=ICMP)')
parser.add_argument('-f', nargs=1, metavar='filename',
    help='Output file name (optional, but recommended)')

args = parser.parse_args()


# Set some default parameters if they're not already set by argument.
# Defaults are port 80, 1 packet/sec, use UDP
if not args.p:
    dstport = 53
else:
    dstport = int(args.p[0])

if args.f:
    f_out = args.f[0]
else:
    f_out = None

# TODO: Add interface and destination address to filter in listener()
if not args.i:
    i_face = "any"
else:
    i_face = args.i

if args.l:
    dest = args.l[0]

if not args.proto:
    proto = 'TCP'
else:
    if args.proto[0] == 't':
        proto = 'TCP'
    elif args.proto[0] == 'u':
        proto = 'UDP'
    elif args.proto[0] == 'i':
        proto = 'ICMP'
    else:
        proto = 'UDP'


# Create a list to store useful information about the packets received
# Contents will vary based on protocol involved, but will always include time
packets = []
gap = 0
message = ''


def listener():
    sniff(filter='not icmp and udp and dst port ' + str(dstport),
        prn=packetstore)


# Add packets to the packet store.  Working only for UDP right now.
# TODO: Create store function for each packet type
def packetstore(p):
    global packets
    p_info = [time.time(), p.id, p[IP].src]
    packets.append(p_info)
    if len(packets) == 8:
        synchronize()
    if len(packets) >= 16:
        check_finish()


# Use the initial 8 packets to determine average packet spacing.  Failure to
# receive any of these will throw off the entire reception.
def synchronize():
    global gap
    gap = (packets[7][0] - packets[0][0]) / 7
    print "Average gap: " + str(gap) + " seconds"


# Look at the last 8 packets received and see if they came in within
# approximately the same spacing as the first sequence.  The closing sequence
# is 0x00FF, represented by 8 no-packets and 8 packets.  This is a unique
# sequence given that the message itself is base64-encoded.
def check_finish():
    global packets
    global gap
    # print "Checking if finished..."
    q = len(packets) - 1
    gap_check = (packets[q][0] - packets[q - 7][0]) / 7
    if gap_check <= gap * 1.1:
        # print "Decoding..."
        p_decode(packets)
        reset()


def p_decode(m):
    global message
    global f_out
    # Start with the 8th and 9th packets to determine bit spacing between them.
    # If it's greater than gap, divide and round to determine by how much and
    # add enough zeroes to buffer.
    a = 7
    b = 8
    tempStr = ''
    while b < (len(m) - 7):
        t = m[b][0] - m[a][0]
        u = round(t / gap)
        tempStr = tempStr + ('0' * (int(u) - 1))
        tempStr = tempStr + '1'
        # Remove next after debugging complete
        # print tempStr
        # The following decoder was inspired by code from Lelouch Lamperouge
        # http://stackoverflow.com/questions/7732496/
        if len(tempStr) >= 8:
            x = int(tempStr[0:8], 2)
            message = message + chr(x)
            # Remove next after debugging complete
            # print chr(x)
            if len(tempStr) == 8:
                tempStr = ''
            else:
                tempStr = tempStr[8:]
        a += 1
        b += 1
    # Create a file called something like proxneak-1372837358 if no filename
    # has been provided.
    # At the moment, I don't have a way to guess the proper extension
    if not f_out:
        f_out = 'proxneak-' + str(int(time.mktime(time.gmtime())))
    tempFile = open(f_out, 'wb')
    tempFile.write(base64.b64decode(message))
    tempFile.close()
    print "Message written out to " + f_out
    exit()


def main():
    listener()


if __name__ == '__main__':
    main()
