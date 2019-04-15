import scapy.all as scapy
import optparse
# import argparse -> new


def getArgs():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Ip target to scan through network")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a network range, For more info use -h")
        exit(1)
    return options


def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arpRequestBroadcast = broadcast/arpRequest
    print("[+] Scanning network...")
    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

    return answeredList



def parsePrintList(answeredList):

    clientsList = []

    for element in answeredList:
        clientDict = {"ip": element[1].psrc,"mac": element[1].hwsrc}
        clientsList.append(clientDict)

    print("IP\t\t\tMAC ADDRESS\n----------------------------------------")
    for clients in clientsList:
        print(clients["ip"] + "\t\t" + clients["mac"])


#option = getArgs()
answerList = scan("10.30.162.0/24")
parsePrintList(answerList)





# scapy.ls(scapy.ARP)
# arpRequestBroadcast.show()
# print(element[1].show())
# print(element[1].psrc + " \t\t " + element[1].hwsrc)

# scapy.srp
# this method send and receive packets
# it returns couple of two lists
# the first is a list of couples(packet sent,answer)
# the second is the list of unanswered packets.
# if you don't set the timeout you'll stuck in there
# print(answered.summary())
