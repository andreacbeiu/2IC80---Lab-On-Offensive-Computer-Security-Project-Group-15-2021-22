import scapy.all as scapy
from scapy.all import * 
from scapy.layers import http

import argparse
import time
import os
#import system

def test(packet):
    if packet.haslayer(http.HTTPResponse):
        if (packet[http.HTTPResponse].Status_Code == "301") and (packet[http.HTTPResponse].Location[0:5] == "https"): #testing if the redirect is towards an httpS url
            print("location MOVED")            
            ACKresponse(packet) #1. ack response to server
            TCPhandshake(packet) #2. initiate TCP handshake with server
            SSLhandshake(packet) #3. initiate SSL Client Hello handshake
            RedirectData() #4. strip off ssl layer and redirect application layer data to target

def ACKresponse(redirect):
    print("Redirect detected...")
    #constructing ACK packet to 301 redirect
    response = Ether() / IP() / TCP()
    response[TCP].seq = redirect[TCP].ack #capture correct seq/ack value
    response[TCP].flags = 'A'
    response[IP].dst = redirect[IP].src #specify destination
    response[TCP].dport = redirect[TCP].sport #specify port
    response[Ether].dst = redirect[Ether].src #specify destination
    sendp(response, iface="enp0s8") #send response ack to the redirect

def TCPhandshake(redirect):
    #constructing first packet in TCP handshake
    #1. change ip tables rule in command to drop RSTs from kernel: iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <insert IP here> -dport <insert port nr here> -j DROP
    #2. fake TCP handshake with scapy
    print("TCP handshake here")

def SSLhandshake(redirect):
    #1. import scapy SSL/TLS extension, see: https://github.com/tintinweb/scapy-ssl_tls
    #2. fake SSL handshake
    print("SSL handshake here")

def RedirectData():
    #1. use SSL/TLS extension to strip layers
    #2. modify sources/destinations/ports
    #3. ensure HTTP headers look good
    #4. send to client over http and not https

def main():
    try:
        while True:
            sniff(iface='enp0s8', prn=test)
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...") 
    

main()
