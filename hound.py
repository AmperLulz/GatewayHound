from scapy.all import sniff, IP, TCP, Raw

def process_packet(packet):
    if 'HTTP' in packet and 'GET' in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        http_method = packet[TCP].payload[Raw].load.split('\r\n')[0]
        http_url = packet[TCP].payload[Raw].load.split('\r\n')[1].split(' ')[1]
        print(f"API Traffic: {source_ip} -> {destination_ip} | {http_method} {http_url}")

sniff(filter="tcp port 80 or tcp port 443", prn=process_packet, store=0)
