#!/usr/bin/python
########################################################################
# Contact:              Nathaniel Carew (njcarew [at] gmail [.] com)
# Company:              http://www.senseofsecurity.com.au/
# Purpose:              Tools to target the Wake On LAN feature.
# Version:              2.0
# Code Repo:            http://code.google.com/p/wol-e
# Credits:              Fadly Tabrani for WOL example
#                       Andrew Trusty for pcapy example
########################################################################
#
# mac osx:
# ports install scapy && ports install py25-pcapy && wget http://oss.coresecurity.com/repo/Impacket-0.9.6.0.tar.gz && tar -xf Impacket-0.9.6.0.tar.gz && cd Imp* && sudo python2.5 setup.py install
#

from __future__ import with_statement
from impacket.ImpactDecoder import *
import socket, struct
import sys, os, datetime, time
import math
import scapy.utils
import scapy.layers.l2
import scapy.route
import scapy
import pcapy

def readf(f):
  with open(f, "r") as fh: return fh.readlines()

def writef(f,l):
  with open(f,'w') as fw: fw.write(l)

def writea(f,l):
  with open(f, 'a') as fh: fh.write(l) 
  
class sniff:
  def __init__(self,args):
    if len(args) < 2:
      print "\t[*] Please specify an adapter collect the WOL passwords from. Eg eth1"
      sys.exit(2)
    print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - WOL Packet Sniffer."
    print "\t[*] WOL packet sniffing has started [*]"
    
    # list all the network devices
    pcapy.findalldevs()

    pc = pcapy.open_live(args, 1024, False, 100)
    pc.setfilter('udp')
      
    # callback for received packets
    def recv_pkts(hdr, data):
      
        packet = str(EthDecoder().decode(data))

        writef("output.txt",packet) 
        lineList = readf('output.txt')
        bcastframe = str(lineList[-7])
        if len(packet) in range(509,514) and 'ffff' in bcastframe:
          lastline1 = str(lineList[-1])
          lastline = lastline1[0:14].replace(' ', '')
          print "\t[*] Detected WOL Client power on: " + lastline + ". Saving to WOLClients.txt"
          writea("WOLClients.txt", lastline + " has been powed on using WOL\n")

        elif len(packet) > 514 and 'ffff' in bcastframe:
          packet = str(packet)
          password = packet[-7:]
          lastline = str(lineList[-1])
	  lastline = lastline[0:14].replace(' ', '')
          passofwol = hex(ord(password[0])).replace('0x', '') + ":" + hex(ord(password[1])).replace('0x', '') + ":" + hex(ord(password[2])).replace('0x', '') + ":" + hex(ord(password[3])).replace('0x', '') + ":" + hex(ord(password[4])).replace('0x', '') + ":" + hex(ord(password[5])).replace('0x', '')
	  print "\t[*] Detected WOL Client power on: " + lastline[0:2] + ":" + lastline[2:4] + ":" + lastline[4:6] + ":" + lastline[6:8] + ":" + lastline[8:10] + ":" + lastline[10:12]
	  print "\t[*] Password in Hex is: " + str(passofwol)
          writea("WOLClients.txt", str(lastline) + " has been powed on with a password of: " + str(passofwol) + "\n")
          
        else:
          pass 
     
    packet_limit = -1
    pc.loop(packet_limit, recv_pkts)
    
def wake_on_lan(version):
    
    # search for Apple MAC addresses in the network and place them into AppleTargets.txt for future use.
    if sys.argv[1] == "-f":
        print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - Scan for Apple devices.\n"

        def long2net(arg):
            if (arg <= 0 or arg >= 0xFFFFFFFF):
                raise ValueError("illegal netmask value", hex(arg))
            return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

        def to_CIDR_notation(bytes_network, bytes_netmask):
            network = scapy.utils.ltoa(bytes_network)
            netmask = long2net(bytes_netmask)
            net = "%s/%s" % (network,netmask)
            if netmask < 20:
                #print net, "is too big. skipping"
                return None

            return net

        def write_output():
          
          def clearArp():
            print "\t[*] Repairing arp cache... please wait"
        
            sp = sys.platform
            if sp == 'darwin':
              os.system('arp -d -a > /dev/null')
            elif sp == 'linux':
              os.system('ip neigh flush all > /dev/null')
            print "\t[*] Arp cache cleared"
               
            
          def c(l):
            return [line.lower().rstrip() for line in l]
          
          def readAndTrim(f):
            return c(readf(f))
          
          def wOutput(x1,x2, x3):
            for s in x1:
              for l in x2:
                if l in s and s not in x3:
                  print "\t[*] Apple device detected: " + str(s) + ". saving to AppleTargets.txt"               
                  writea('AppleTargets.txt', str(s) + "\n")
             
          scanResults = readAndTrim('netscan.txt')
          loggedLines = readAndTrim('AppleMAC.lst')
          targetLines = readAndTrim('AppleTargets.txt')
          
          wOutput(scanResults,loggedLines,targetLines)
          clearArp()
          print "\n\t[*] scan completed [*]\n" 
          sys.exit(2)
          
        def scan_and_print_neighbors(net, interface):
          print "\t[*] arping", net, "on", interface
          ans,unans = scapy.layers.l2.arping(net, iface=interface, timeout=1, verbose=False)#, verbose=True)
          d=open('netscan.txt', 'w')
          for s,r in ans.res:
            array = []
            array.append(r.sprintf("%Ether.src% %ARP.psrc%"))
            for item in array:
              d.write("%s\n" % item)
          d.close()
          write_output()
          
        # horrid but seems to work on both linux and mac.  
        l = os.popen("ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{ print $2}' | head -1 | sed 's/addr\://g'").read().rstrip()
        
        for route in scapy.config.conf.route.routes:
          network = route[0]
          netmask = route[1]
          interfa = route[3]
          localip = route[4]
          
          if netmask <= 0x0 or netmask == 0xFFFFFFFF:
            continue
              # network == 0 or
          if l == localip:
            net = to_CIDR_notation(network, netmask)
            if net:
              scan_and_print_neighbors(net, interfa)
            

    # Manual WOL Enabling for single addresses
    if sys.argv[1] == "-m":
        if len(sys.argv) < 3:
            print "\n\t[-] Please specify a MAC address\n"
            sys.exit(2)
        macaddress = sys.argv[2]
        if len(macaddress) == 12:
            pass
        elif len(macaddress) == 12 + 5:
            sep = macaddress[2]
            macaddress = macaddress.replace(sep, '')
        else:
            print "\n\t[*] Please check the MAC address format. Example: 00:1A:2B:3C:4D:5E\n"
            sys.exit(2)
        if len(sys.argv) < 4:
            print "\n\t[*] No broadcast address or destination port detected, using the default of 255.255.255.255 and 9 respectively\n"
            bcast = '255.255.255.255'
            destport = int(9)
        else:
            bcast = sys.argv[4]
            destport = int(sys.argv[6])
        wolpass = "0"
        if len(sys.argv) > 7:
            wolpass = sys.argv[8]
        if len(wolpass) == 12:
            pass
        elif len(wolpass) == 12 + 5:
            sep = wolpass[2]
            wolpass = wolpass.replace(sep, '')
        else:
            wolpass = "empty"

        print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - Powers on computers in the network with WOL enabled.\n"
        print "\t\tMac is: " + macaddress
        print "\t\tBroadcast is: " + str(bcast)
        print "\t\tDest Port is: " + str(destport)
        print "\t\tPassword is: " + wolpass
        print "\n\n"
        
        if wolpass != "empty":
          data = ''.join(['FFFFFFFFFFFF', macaddress * 16, wolpass])
        else:
          data = ''.join(['FFFFFFFFFFFF', macaddress * 16])
        send_data = ''

        for i in range(0, len(data), 2):
          send_data = ''.join([send_data, struct.pack('B', int(data[i: i + 2], 16))])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(send_data, (bcast, destport))
        print "\t[*] Attempt to power on " + sys.argv[2] + " completed\n"
        sys.exit(2)

    # WOL Password Sniffing Section
    if sys.argv[1] == "-s":
      sniff(sys.argv[3])

    # Attempt to wake all Apple clients collected during an earlier scan using -f
    if sys.argv[1] == "-fa":
        print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - WOL Detected Apple clients."
        bcast = '255.255.255.255'
        apples = os.getcwd() + "/" + "AppleTargets.txt"
        if os.path.exists(apples) == False:
                print "\n\t[*] Please ensure you have the AppleTargets.txt file in the current working directory.\n"
                sys.exit(2)
        if len(sys.argv) < 3:
                print "\n\t[*] No destination port detected, using 9 as the default"
                port = int(9)
        else:
                print "\t[*] Custom port detected: " + str(sys.argv[3])
                port = int(sys.argv[3])
        f=open(apples)
        linenums = 0
        for lines in f:
                linenums = linenums + 1
                macaddress = lines[0:17]
                sep = macaddress[2]
                macaddress = macaddress.replace(sep, '')
                data = ''.join(['FFFFFFFFFFFF', macaddress * 16])
                send_data = ''

                for i in range(0, len(data), 2):
                        send_data = ''.join([send_data,
                                struct.pack('B', int(data[i: i + 2], 16))])

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(send_data, (bcast, port))
                time.sleep(0.005)
        print "\n\t[*] " + str(linenums) + " detected Apple clients have been sent WOL requests, Exiting.\n"
        f.close()
        sys.exit(2)

# WOL Bruteforcer against a list of MAC ranges (time intensive due to the amount of possible addresses)
    if sys.argv[1] == "-a":
        print "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - WOL Bruteforce MAC ranges."
        bcast = '255.255.255.255'
        macs = os.getcwd() + "/" + "bfmac.lst"
    else:
        print "\n\t[*] Unknown command, please see the help documentation for more information\n"
        sys.exit(2)
    if len(sys.argv) < 3:
        print "\n\t[*] No destination port detected, using 9 as the default"
        port = int(9)
    else:
        print "\t[*] Custom port detected: " + str(sys.argv[3])
        port = int(sys.argv[3])
    if os.path.exists(macs) == False:
        print "\n\t[*] Please ensure you have the bfmac.lst file in the current working directory.\n"
        sys.exit(2)     
    else:
        f=open(macs)
        print "\t[*] WOL Bruteforcing has started."
        for line in f:
                print "\t[*] Now bruteforcing " + str(line).rstrip() + ":00:00 -> " + str(line).rstrip() + ":FF:FF"
                for y in range(0, 255):
                        for z in range(0, 255):
                                line = line.rstrip()
                                if len(line) < 11 or len(line) > 11:
                                        print "\n\t[*] MAC address format incorrect, please fix the contents of bfmac.lst\n\t[*] Eg: 00:12:34:46\n"
                                        sys.exit(2)
                                macaddress = line + ":" + hex(y).replace('0x', '').zfill(2) + ":" + hex(z).replace('0x', '').zfill(2)
                                sep = macaddress[2]
                                macaddress = macaddress.replace(sep, '')

                                data = ''.join(['FFFFFFFFFFFF', macaddress * 16])
                                send_data = '' 

                                for i in range(0, len(data), 2):
                                        send_data = ''.join([send_data,
                                                struct.pack('B', int(data[i: i + 2], 16))])

                                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                                sock.sendto(send_data, (bcast, port))
                                time.sleep(0.001)
        f.close()
        print "\n\t[*] Bruteforce of MAC ranges completed. Exiting [*]\n"
        sys.exit(2)

if __name__ == '__main__':

  version = "1.0"
  help_message = "\n\t[*] WOL-E " + version + " [*]\n\t[*] Wake on LAN Explorer - A collection of WOL tools. [*]\n\t[*] by Nathaniel Carew [*]\n\n\t[*] For help use: wol-e.py -h\n"

  if len(sys.argv) < 2:
    print help_message
    sys.exit(2)

  if sys.argv[1] == "-h":
          bold = "\033[1m"
          nobold = "\033[0;0m"
          print bold + "\n[*] WOL-E " + version + "\n[*] Wake on LAN Explorer - A collection a WOL tools.\n[*] by Nathaniel Carew\n" + nobold
            
          print "\t-m"          
          print bold + "\t\tWaking up single computers." + nobold
          print "\t\tIf a password is required use the -k 00:12:34:56:78:90 at the end of the above command." + nobold
          print bold + "\t\twol-e.py -m 00:12:34:56:78:90 -b 192.168.1.255 -p <port> -k <pass>" + nobold
          print "\t\tDefaults: "
          print "\t\tPort: 9"
          print "\t\tBroadcast: 255.255.255.255"
          print "\t\tPass: empty\n"
          
          print "\t-s"
          print bold + "\t\tSniffing the network for WOL requests and passwords." + nobold
          print "\t\tAll captured WOL requests will be displayed on screen and written to WOLClients.txt."
          print bold + "\t\twol-e.py -s -i eth0\n" + nobold
            
          print "\t-a"
          print bold + "\t\tBruteforce powering on WOL clients." + nobold
          print bold + "\t\twol-e.py -a -p <port>" + nobold
          print "\t\tPlace the address ranges into the bfmac.lst that you wish to bruteforce."
          print "\t\tThey should be in the following format:"
          print "\t\t00:12:34:56"
          print "\t\tDefault port: 9\n"
          
          print "\t-f"
          print bold + "\t\tDetecting Apple devices on the network for WOL enabling." + nobold
          print "\t\tThis will output to the screen and write to AppleTargets.txt for detected Apple MAC's."
          print bold + "\t\twol-e.py -f\n" + nobold

          print "\t-fa"
          print bold + "\t\tAttempt to wake all detected Apple targets in AppleTargets.txt." + nobold
          print "\t\tThis will send a single WOL packet to each client in the list and tell you how many clients were attempted."
          print bold + "\t\twol-e.py -fa\n" + nobold
          
          sys.exit(2)

  wake_on_lan(version)
