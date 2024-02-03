from scapy.all import *

def check_for_malicious_commands(payload):
    malicious_commands = ["TSUNAMI", "PAN", "UDP" , "UNKNOWN ", "GETSPOOFS", "SPOOFS", 
                          "DISABLE", "ENABLE", "KILL", "GET", "VERSION", "KILLALL", "HELP", "IRC", "SH"]
    
    for command in malicious_commands:
        if command in payload:
            return True
    
    return False

def check_irc_kaiten(packet):
    if TCP in packet and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "NICK" in payload:
            src_port = packet[TCP].sport
            malicious_commands_present = check_for_malicious_commands(payload)
            
            if src_port != 6667 or malicious_commands_present:
                print("Possible IRC Kaiten traffic detected.")

file_path = "kaitenverkeer.pcap"
packets = rdpcap(file_path)

for packet in packets:
    check_irc_kaiten(packet)
