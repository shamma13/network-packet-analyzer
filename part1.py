import socket
import struct


def print_nb_packets(pcap):
    total_packets = 0
    # source_ip_counts = {}

    for ts, buf in pcap: #for each iteration, loop unpacks timestamp and buffer
        total_packets += 1 #increment for each packet
    return total_packets

def get_source_ip_counts(pcap):
    source_ip_counts = {}
    for ts, buf in pcap:
        # Parse packet header
        eth_header = buf[:14]
        eth_type = struct.unpack('!H', eth_header[12:14])[0]

        if eth_type == 0x0800:  # IPv4 in hexadecimal
            ip_header = buf[14:34]
            ip_length = (ip_header[0] & 0xF) * 4 #calculate length of ipv4 header, convert to bytes
            ip_data = buf[14:14 + ip_length] #extract ipv4 packet data, header + payload

            # Extract source IP address from ipv4 header
            src_ip = socket.inet_ntoa(ip_data[12:16])

            # Increment source IP count
            source_ip_counts[src_ip] = source_ip_counts.get(src_ip, 0) + 1

    return source_ip_counts


def get_dest_port_counts(pcap):
    dest_port_counts = {}
    for ts, buf in pcap:
        # Parse packet header
        eth_header = buf[:14]
        eth_type = struct.unpack('!H', eth_header[12:14])[0]

        if eth_type == 0x0800:  # IPv4
            ip_header = buf[14:34]
            ip_proto = ip_header[9] # Protocol field at offset 9
            ip_length = (ip_header[0] & 0xF) * 4
            ip_data = buf[14:14 + ip_length]

            # Check if the packet is TCP and has enough data for TCP header
            if ip_proto == 6:
                tcp_header = buf[34:54]
                dest_port = struct.unpack('!H', tcp_header[2:4])[0]


                # Increment destination port count
                dest_port_counts[dest_port] = dest_port_counts.get(dest_port, 0) + 1

    return dest_port_counts

def get_source_dest_pairs(pcap):
    source_dest_pairs = {}
    for ts, buf in pcap:
        # Parse packet headers
        eth_header = buf[:14]
        eth_type = struct.unpack('!H', eth_header[12:14])[0]

        if eth_type == 0x0800:  # IPv4
            ip_header = buf[14:34]
            ip_proto = ip_header[9]
            ip_length = (ip_header[0] & 0xF) * 4
            ip_data = buf[14:14 + ip_length]

            # Check if it's TCP packet
            if ip_proto == 6:
                tcp_header = buf[34:54]
                dest_port = struct.unpack('!H', tcp_header[2:4])[0]
                src_ip = socket.inet_ntoa(ip_data[12:16])

                # Update source-destination pairs dictionary
                key = (src_ip, dest_port)
                source_dest_pairs[key] = source_dest_pairs.get(key, 0) + 1

    return source_dest_pairs


def main():
    files = ["C:\\Users\\Shamma\\Desktop\\COMP 445\\file1.pcap", "C:\\Users\\Shamma\\Desktop\\COMP 445\\file2.pcap", "C:\\Users\\Shamma\\Desktop\\COMP 445\\file3.pcap"]
    total_packets_all = 0
    source_ip_counts_all = {}
    dest_port_counts_all = {}
    source_dest_pairs_all = {}

    with open('part1_output.txt', 'w') as output_file:

        output_file.write("Task 1a) Total packets in each file:\n")
        for filename in files:
            with open(filename, 'rb') as f:
                pcap = [(ts, buf) for ts, buf in read_pcap_file(f)]
                total_packets = print_nb_packets(pcap)
                output_file.write(f"\nTotal packets in, {filename}, :, {total_packets}")
                total_packets_all += total_packets
        output_file.write(f"\nTotal packets in all files:, {total_packets_all}\n")
        

        output_file.write("\nTask 1b) Distinct source IP addresses and number of packets for each IP address:\n")
        for filename in files:
            with open(filename, 'rb') as f:
                pcap = [(ts, buf) for ts, buf in read_pcap_file(f)]
                source_ip_counts = get_source_ip_counts(pcap)
                source_ip_counts_all.update(source_ip_counts)
        
        # Sort source IP counts dictionary by packet counts in descending order
        sorted_source_ip_counts = sorted(source_ip_counts_all.items(), key=lambda x: x[1], reverse=True)

        # Print distinct source IP addresses and number of packets for each IP address
        for src_ip, packet_count in sorted_source_ip_counts:
            output_file.write(f"Source IP: {src_ip}, Packets: {packet_count}\n")

    
        output_file.write("\nTask 1c) Distinct destination TCP ports and number of packets sent to each port:\n")
        
        for filename in files:
            with open(filename, 'rb') as f:
                pcap = [(ts, buf) for ts, buf in read_pcap_file(f)]
                dest_port_counts = get_dest_port_counts(pcap)
                for dest_port, packet_count in dest_port_counts.items():
                    dest_port_counts_all[dest_port] = dest_port_counts_all.get(dest_port, 0) + packet_count
        
        # Sort source IP counts dictionary by packet counts in descending order
        sorted_dst_tcp_counts = sorted(dest_port_counts_all.items(), key=lambda x: x[1], reverse=True)
        for dest_port, packet_count in sorted_dst_tcp_counts:
            output_file.write(f"TCP Port: {dest_port}, Packets: {packet_count}\n")


        output_file.write("\nTask 1d) Distinct source IP and destination TCP port pairs, sorted by packet counts:\n")

        for filename in files:
            with open(filename, 'rb') as f:
                pcap = [(ts, buf) for ts, buf in read_pcap_file(f)]
                source_dest_pairs = get_source_dest_pairs(pcap)
                for pair, count in source_dest_pairs.items():
                    source_dest_pairs_all[pair] = source_dest_pairs_all.get(pair, 0) + count

        # Sort source-destination pairs dictionary by packet counts in descending order
        sorted_pairs = sorted(source_dest_pairs_all.items(), key=lambda x: x[1], reverse=True)

        # Print distinct source IP and destination TCP port pairs
        for pair, count in sorted_pairs:
            src_ip, dest_port = pair
            output_file.write(f"Source IP: {src_ip}, Destination TCP Port: {dest_port}, Packets: {count}\n")

def read_pcap_file(file):
    pcap_header = file.read(24) #first 24 bytes contain the file header
    while True:
        header = file.read(16) #next 16 bytes contain the packet header
        if len(header) < 16:  #incomplete data or end of file
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', header) #unpack header info
        buf = file.read(incl_len) #read packet data based on included length(actual length of packet data)
        yield (ts_sec, buf)


if __name__ == "__main__":
    main()
