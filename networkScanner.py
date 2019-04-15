import scapy.all as scapy
import optparse
# import argparse for python3


# Getting arguments from user
def getArgs():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Ip target to scan through network")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a network range, For more info use -h")
        exit(1)
    return options


# Creating broadcast frame for Arp and getting answers
def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arpRequestBroadcast = broadcast/arpRequest
    print("[+] Scanning network...")
    answeredList = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

    return answeredList


# Parsing results for user interface
def parsePrintList(answeredList):

    clientsList = []

    for element in answeredList:
        clientDict = {"ip": element[1].psrc,"mac": element[1].hwsrc}
        clientsList.append(clientDict)

    print("IP\t\t\tMAC ADDRESS\n----------------------------------------")
    for clients in clientsList:
        print(clients["ip"] + "\t\t" + clients["mac"])


option = getArgs()
answerList = scan(option.target)
parsePrintList(answerList)

