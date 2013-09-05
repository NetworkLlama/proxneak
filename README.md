proxneak
========

Requirements:
 - Python on sending and receiving side (basic installation should suffice)
 - pcapy on the receiving side

A means of exfiltrating data through anything that allows a connection,
including regenerative proxies.

Thanks to:
  Stephen Sims for getting me started on Python through a grueling SANS SEC660 course
  Lelouch Lamperouge for some inspiration on bits-to-bytes conversion
  Silver Moon for his pcapy code
  Catherine for putting up with me while I'm coding

A few notes, some learned the hard way while troubleshooting:

The rate setting (-r) is the number of packets per second, so it's the inverse of the
gap between packets (-r 10 is 10pps or ~100ms between packets).  Be realistic about the
capabilities of your network.  Sending within your own system (localhost to localhost)
at 100pps might work, but unless you're on a network that can actually do full gigabit,
it's not going to work.  There's a reason the default is 1pps, and even that can have
problems.

Wireless makes life difficult.  The odds of a packet being delayed and throwing
off the entire thing is extremely high, such that anything past a couple of hundred
bytes has a very strong tendency to fail unless your gap is greater than about eight
seconds.
