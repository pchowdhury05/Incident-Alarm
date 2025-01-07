#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

incident_count = 0
user = ' ' 

def packetcallback(packet):
    global incident_count

    if packet.haslayer(TCP):

        # check for Null scan: 
        if packet[TCP].flags == 0:
            incident_count += 1
            print("ALERT #" + str(incident_count) + ": NULL scan is detected from " + str(packet[IP].src) + " (TCP port " + str(packet[TCP].dport) + ")!")

        # check for Xmas scan:
        elif packet[TCP].flags.F and packet[TCP].flags.U and packet[TCP].flags.P:
            incident_count += 1
            print("ALERT #" + str(incident_count) + ": Xmas scan is detected from " + str(packet[IP].src) + " (TCP port " + str(packet[TCP].dport) + ")!")

        # check for FIN scan:
        elif packet[TCP].flags.F:
            if packet[TCP].flags.A == 0:
                incident_count += 1
                print("ALERT #" + str(incident_count) + ": FIN scan is detected from " + str(packet[IP].src) + " (TCP port " + str(packet[TCP].dport) + ")!")

        # check for SMB scan:
        elif packet[TCP].sport == 445 or packet[TCP].dport == 445 or packet[TCP].sport == 139 or packet[TCP].dport == 139:
            incident_count += 1
            print("ALERT #" + str(incident_count) + ": SMB scan is detected from " + str(packet[IP].src) + " (TCP port " + str(packet[TCP].dport) + ")!")

        # check for RDP scan:
        elif packet[TCP].sport == 3389 or packet[TCP].dport == 3389:
            incident_count += 1
            print("ALERT #" + str(incident_count) + ": RDP scan detected from " + str(packet[IP].src) + " (TCP port " + str(packet[TCP].dport) + ")!")

        # check for VNC scan:
        elif packet[TCP].dport == 5900 or packet[TCP].dport == 5901:
            incident_count += 1
            print("ALERT #" + str(incident_count) + ": VNC scan detected from " + str(packet[IP].src) + " (TCP port " + str(packet[TCP].dport) + ")!")

    try:
        p = packet[TCP].load.decode("ascii")

        # check for Nikto scan:
        if 'Nikto' in p:
            incident_count += 1
            print("ALERT #" + str(incident_count) + ": Nikto scan is detected from " + str(packet[IP].src) + " (TCP port " + str(packet[TCP].dport) + ")!")


        # check usernames and passwords sent in-the-clear via FTP protocol:
        if packet.haslayer(TCP) and packet[TCP].dport == 21:
            global user
            protocol = "FTP"
        if "USER" in p:
            user = str(p)
            user = user.lstrip("USER ")   
        if "PASS" in p:
            password = str(p)
            password = user.lstrip("PASS ")
            incident_count += 1
            print("ALERT #" + str(incident_count) + ": Usernames and passwords sent in-the-clear (" + protocol + ") {username: " + user + ", password: " + password + "}")


        # check usernames and passwords sent in-the-clear via HTTP Basic Authentication:
        if packet.haslayer(TCP) and packet[TCP].dport == 80 or packet[TCP].dport == 8000:
            protocol = "HTTP"
            if 'Authorization: Basic' in p:
                for line in p.splitlines():
                    if 'Authorization: Basic' in line:
                        line = line.strip('Authorization: Basic').strip()
                        decoded_credentials = base64.b64decode(line).decode('utf-8')
                        username, password = decoded_credentials.split(':', 1)
                        incident_count += 1
                        print("ALERT #" + str(incident_count) + ": Usernames and passwords sent in-the-clear (" + protocol + ") {username: " + username + ", password: " + password + ")")
                        

        # check usernames and passwords sent in-the-clear via IMAP protocol:
        if packet.haslayer(TCP) and packet[TCP].dport == 143 or packet[TCP].dport == 993:
            protocol = "IMAP"
            if "LOGIN" in p:
                imap_packet = str(p)
                imap_packet = imap_packet.lstrip("3 LOGIN ")
                imap_packet = imap_packet.split(" ")
                imap_packet[1] = imap_packet[1].lstrip('"')
                imap_packet[1] = imap_packet[1].rstrip('"')
                incident_count += 1
                print("ALERT #" + str(incident_count) + ": Usernames and passwords sent in-the-clear (" + protocol + ") {username: " + imap_packet[0] + ", password: " + imap_packet[1] + "}")

                                           
    except Exception as e:
        # Uncomment the below and comment out `pass` for debugging, find error(s)
        #print(e)
        pass



# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
