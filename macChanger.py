import optparse
import subprocess


def getArgs():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="interface to change its Mac Address")
    parser.add_option("-m", "--mac", dest="macAddress", help="new Mac address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify interface")
    if not options.macAddress:
        parser.error("[-] Please specify new Mac Address")
    return options


def changeMac(interface, newMac):
    print("[+] Changing Mac Address..")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether",newMac])
    subprocess.call(["ifconfig", interface, "up"])


options = getArgs()
changeMac(options.interface, options.macAddress)
