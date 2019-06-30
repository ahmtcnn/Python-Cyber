#!/usr/bin/env python
# coding=utf-8
import scapy.all as scapy


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processSniffedPacket)  # ,filter="udp", "arp", "tcp" "port 21" (ftp filtreleme) -> bu parametreleri de girebilirsin.


def getMac(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arpRequestBroadcast = broadcast/arpRequest

    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

    return answeredList[0][1].hwsrc


def processSniffedPacket(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        realMac = getMac(packet[scapy.ARP].psrc)
        responseMac = packet[scapy.ARP].hwsrc
        try:
            if realMac != responseMac:
                print("[+] You are under attack")
        except IndexError:
            pass


sniff("eth0")
