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
import time
import socket

parser = argparse.ArgumentParser(description='Receive data from any ' +
    'connection that allows traffic to pass through, even if it\'s a ' +
    'regenerative proxy. Be aware that random latency can cause problems ' +
    'at the receiving end.')
parser.add_argument('-l', nargs=1, metavar='<src>',
    help='Listener IP address (not currently implemented')
parser.add_argument('-p', nargs=1, metavar='port',
    help='Listener port (default is 80)')
parser.add_argument('--proto', nargs=1, metavar='',
    help='Protocol to use (T=TCP (default), U=UDP, I=ICMP')
parser.add_argument('-f', nargs=1, metavar='filename',
    help='Source file name')
parser.add_argument('-r', nargs=1, metavar='integer',
    help='Number of packets to send per second ' +
    '(default 1; recommended is 5 or less)')
parser.add_argument('-u', action='store_true',
    help='Source is in Unicode')
parser.add_argument('-z', action='store_true',
    help='Compress content before sending')

args = parser.parse_args()

# Set some default parameters if they're not already set by argument.
# Defaults are port 80, 1 packet/sec, use TCP
if args.l:
    dest = args.l[0]
if not args.p:
    dstport = 80
else:
    dstport = int(args.p[0])
if args.f:
    fin = args.f[0]
if not args.r:
    pps = 1
else:
    pps = int(args.r[0])

unistatus = args.u
zipstatus = args.z

if not args.proto:
    proto = 'TCP'
else:
    if args.proto[0] == 'T':
        proto = 'TCP'
    elif args.proto[0] == 'U':
        proto = 'UDP'
    elif args.proto[0] == 'I':
        proto = 'ICMP'
    else:
        proto = 'TCP'

# TODO:
# Create listener
# Create time checker
# Create interpreter
