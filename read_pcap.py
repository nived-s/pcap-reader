from scapy.all import *
from tqdm import tqdm


def main():
    pcap_file = "demo-2.pcap"
    
    packets = rdpcap(pcap_file)
    df = extract_packet_data(packets)

    
def extract_packet_data(packets):
    packet_data = []

    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        # if IP in packet:
        #     src_ip = packet[IP].src
        #     dst_ip = packet[IP].dst
        #     protocol = packet[IP].proto
        #     versionnnn = packet[IP].version
        #     size = len(packet)
        #     packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size, "version":versionnnn})
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            version = packet[IP].version
            size = len(packet)
            ttl = packet[IP].ttl
            identification = packet[IP].id
            flags = packet[IP].flags
            frag_offset = packet[IP].frag
            checksum = packet[IP].chksum
            options = packet[IP].options

            packet_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "version": version,
                "size": size,
                "ttl": ttl,
                "identification": identification,
                "flags": flags,
                "fragment_offset": frag_offset,
                "checksum": checksum,
                "options": options
            })


    for i in range(len(packet_data)):
        print(packet_data[i])

    return packet_data

if __name__ == "__main__":
    main()