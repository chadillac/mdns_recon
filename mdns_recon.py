#!/usr/bin/python2

##  The MIT License (MIT)
##  
##  Copyright (c) 2015 Chad Seaman
##  
##  Permission is hereby granted, free of charge, to any person obtaining a copy
##  of this software and associated documentation files (the "Software"), to deal
##  in the Software without restriction, including without limitation the rights
##  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
##  copies of the Software, and to permit persons to whom the Software is
##  furnished to do so, subject to the following conditions:
##  
##  The above copyright notice and this permission notice shall be included in all
##  copies or substantial portions of the Software.
##  
##  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
##  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
##  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
##  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
##  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
##  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
##  SOFTWARE.

from scapy.all import *
import re

target_ip = sys.argv[1]

# mdns query string
query = "_services._dns-sd._udp.local"

# build and send the packet
pkt=IP(dst=target_ip)/UDP(dport=5353)/DNS(rd=1,qd=DNSQR(qname=query,qtype='PTR'))
ans=sr1(pkt,verbose=0,timeout=2)

# drop timeouts and ICMP unreachables
if ans is None:
   quit()
elif ans.haslayer(ICMP):
   quit()

print "\n"+target_ip+" - START"
print "["+query+"]==="
print ans
print "["+query+"]==="

replies = {query:len(ans)}
ans = str(ans).split("\n")

services = []

# loop over returned service names, format and store them
for entry in ans:
    chars = list(entry)
    entry_clean = ""
    for a_char in chars:
        if a_char in string.printable:
            entry_clean += a_char
    service = re.search('_[a-z_-]+',entry_clean)
    if service is not None:
        services.append(str(service.group(0)).rstrip())

# remove the first one (we've already queried it)
services = services[1:]

# query each service, output their replies and log their lengths
for service_type in services:
    service_type = service_type.replace('_tcp','')
    service_type = service_type+"._tcp.local."
    print "["+service_type+"]==="
    pkt=IP(dst=target_ip)/UDP(dport=5353)/DNS(rd=1,qd=DNSQR(qname=service_type,qtype='PTR'))
    ans=sr1(pkt,verbose=0,timeout=2)
    print ans
    print "["+service_type+"]==="
    if ans is not None:
        replies[service_type] = len(ans)

# output the final list of services and their associated response length
print replies
print target_ip+" - END"
