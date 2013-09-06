===============================================================================
                                   proxneak
===============================================================================

A means of exfiltrating data through anything that allows a connection,
including regenerative proxies.

The idea came to me while I was tinkering with an application-proxy firewall.
For those unfamiliar, these devices use a deeper level of packet inspection to
determine the protocol in use and match it to a rule.  For example, if generic
HTTP is allowed, then someone trying to tunnel, say, SSH over it would find
the connection dropped.  While there are some clever ways out there of hiding
one protocol in another (HTTP over DNS comes to mind), I wanted a way to send
information regardless of the filters.

Proxneak does this by utilizing the basic behavior of the proxies (if there is
one) to send the packet on if it matches the parameters.  Many proxies will
establish a TCP connection first to see if it's allowed and then look at the
contents to see if it should be closed off.  In part to prevent something
sneaking through in the structure, they regenerate the packet entirely, often
resulting in a TCP connection from an OS different from the originating system
(for example, FreeBSD instead of Windows).  But it still sends a packet, and
that a packet is sent can still be a form of information.

(Note that this might also be a way of sending information (albeit slowly)
that the NSA can't reasonably track.  Saving all of the SYN packets that cross
the Internet just isn't a practical way of doing business.

Requirements
============
 - Python 2.7 on sending and receiving side (basic installation may suffice,
   python-argparse sometimes needs to be added)
 - pcapy on the receiving side


Install
=======
Download the latest version from https://github.com/NetworkLlama/proxneak.git


Command Line
============
Sender
------
* -h, --help   show this help message and exit
* -s <src>     Source IP address (not currently implemented
* -d <dst>     Destination IP address (required)
* -p port      Destination port (default is 53)
* --proto      Protocol to use (t=TCP, u=UDP (default), i=ICMP); ICMP requires
               root access
* -f filename  Input file name
* -r integer   Number of packets to send per second (default 1; recommended is
               5 or less)
* -v           Verbose mode (be aware that this may leave behind artifacts)
* -V           Display version number
* -z           Compress content with bzip2 before sending

Receiver
--------
* -h, --help          show this help message and exit
* -i <interface>      Listener network interface (required)
* -s <src>            Sending IP address (optional)
* -d <dst>            Receiving IP address (optional)
* -p <port>           Listener port (default is 53)
* --proto <protocol>  Protocol to use (T=TCP, U=UDP (default), I=ICMP)
* -f filename         Output file name (required)
* -r filename         Read a list file in (requires --proto be specified)
* -v                  Verbose mode
* -V                  Display version number
* -z                  Incoming content is compressed with bzip2


Usage Notes
===========
* Sending to a system set to drop the inbound packets seems to work best (at
  least with regard to UDP).
* If you send with -z, you must receive with -z.  There's no automatic checking
  yet for whether incoming material is compressed.
* The rate setting (-r) is the number of packets per second, so it's the
  inverse of the gap between packets (-r 10 is 10pps or ~100ms between
  packets).  Be realistic.  Sending at 100pps might work if you're on a network
  that can actually do full gigabit, it's not going to work.  There's a reason
  the default is 1pps, and even that can have problems.
* Wireless makes life difficult.  The odds of a packet being delayed and
  throwing off the entire thing is extremely high, such that anything past a
  couple of hundred bytes has a very strong tendency to fail unless your gap is
  greater than about eight seconds.


Thanks
======
* Stephen Sims for getting me started on Python in a grueling SANS SEC660 class
* Lelouch Lamperouge for some inspiration on bits-to-bytes conversion
* Silver Moon for his pcapy code
* Catherine for putting up with me while I'm coding


Contact
=======
Jarrod Frates (jfrates@gmail.com)
http://llamasinmynetwork.com
