import argparse
import socket
import struct

# Read packets from pcap file
def read_pcap_file(file):
    pcap_header = file.read(24) #read header
    packets = []
    while True:
        header = file.read(16)
        if len(header) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', header)
        buf = file.read(incl_len)
        packets.append((ts_sec, buf))
    return packets

# Check if a packet is TCP and extract source IP, destination IP, and destination port
def extract_tcp_info(packet):
    eth_length = 14
    ip_header = packet[eth_length:20 + eth_length]

    iph = struct.unpack('!BBHHHBBH4s4s', ip_header) #unpack 
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])

    if protocol == 6:  # TCP
        tcp_header = packet[20 + eth_length:40 + eth_length]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        dest_port = tcph[1]
        return src_ip, dest_ip, dest_port
    else:
        return None, None, None


def extract_udp_info(packet):
    eth_length = 14
    ip_header = packet[eth_length:20 + eth_length]

    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])

    if protocol == 17:  # UDP
        udp_header = packet[20 + eth_length:28 + eth_length]
        udph = struct.unpack('!HHHH', udp_header)
        dest_port = udph[1]
        return src_ip, dest_ip, dest_port
    else:
        return None, None, None



def extract_attempts(packets, target_ip, protocol, probing_width, min_packets_probing, scanning_width, min_packets_scanning):
    probing_attempts = {}
    scanning_attempts = {}

    # Sort packets by time
    packets.sort(key=lambda x: x[0])
    

    # Sort packets by port number
    packets_by_port = {}
    for ts, packet in packets:
        if protocol == "tcp":
            src_ip, dest_ip, dest_port = extract_tcp_info(packet)
        elif protocol == "udp":
            src_ip, dest_ip, dest_port = extract_udp_info(packet)
        else:
            raise ValueError("Invalid protocol specified")

        if dest_ip == target_ip and dest_port:
            if dest_port not in packets_by_port:
                packets_by_port[dest_port] = []
            packets_by_port[dest_port].append((src_ip, ts))

    # Find clusters for probing and scanning
    for port, port_packets in packets_by_port.items():
        port_packets.sort(key=lambda x: x[1])  # Sort by timestamp
        current_probe = []
        current_scan = []
        last_probe_ts = None
        last_scan_src_ip = None

        for src_ip, ts in port_packets:
            if current_probe:
                if ts - last_probe_ts <= probing_width:
                    current_probe.append((src_ip, ts))
                else:
                    if len(current_probe) >= min_packets_probing:
                        probing_attempts[port] = current_probe
                    current_probe = [(src_ip, ts)]
                last_probe_ts = ts
            else:
                current_probe.append((src_ip, ts))
                last_probe_ts = ts

            if current_scan:
                if src_ip == last_scan_src_ip:
                    current_scan.append((src_ip, ts))
                else:
                    if len(current_scan) >= min_packets_scanning:
                        if last_scan_src_ip not in scanning_attempts:
                            scanning_attempts[last_scan_src_ip] = []
                        scanning_attempts[last_scan_src_ip].append((port, len(current_scan)))
                    current_scan = [(src_ip, ts)]
                last_scan_src_ip = src_ip
            else:
                current_scan.append((src_ip, ts))
                last_scan_src_ip = src_ip

        # Check for remaining probes and scans
        if len(current_probe) >= min_packets_probing:
            probing_attempts[port] = current_probe
        if len(current_scan) >= min_packets_scanning:
            if last_scan_src_ip not in scanning_attempts:
                scanning_attempts[last_scan_src_ip] = []
            scanning_attempts[last_scan_src_ip].append((port, len(current_scan)))

    # Format probing reports
    probing_reports = []
    for port, attempts in probing_attempts.items():
        probing_reports.append((attempts[0][0], port, len(attempts)))

    # Format scanning reports
    scanning_reports = []
    for src_ip, attempts in scanning_attempts.items():
        for port, count in attempts:
            scanning_reports.append((src_ip, count))

    return probing_reports, scanning_reports


def main():
    parser = argparse.ArgumentParser(description='Process pcap file and identify probes and scans.')
    parser.add_argument('-f', '--file', type=str, help='PCAP file path')
    parser.add_argument('-t', '--target', type=str, help='Target IP address')
    parser.add_argument('-l', '--probing_width', type=int, help='Width for probing in seconds')
    parser.add_argument('-m', '--min_probing_packets', type=int, help='Minimum number of packets in a probing')
    parser.add_argument('-n', '--scanning_width', type=int, help='Width for scanning in port ID')
    parser.add_argument('-p', '--min_scanning_packets', type=int, help='Minimum number of packets in a scanning')
    args = parser.parse_args()

    if not args.file or not args.target or not args.probing_width or not args.min_probing_packets or not args.scanning_width or not args.min_scanning_packets:
        parser.error('Missing argument(s). Please provide all required arguments.')

    with open(args.file, 'rb') as f:
        packets = read_pcap_file(f)
        probing_reports_tcp, scanning_reports_tcp = extract_attempts(packets, args.target, "tcp", args.probing_width, args.min_probing_packets, args.scanning_width, args.min_scanning_packets)

        # Re-read the pcap file to process UDP packets separately
        f.seek(0)
        packets = read_pcap_file(f)
        probing_reports_udp, scanning_reports_udp = extract_attempts(packets, args.target, "udp", args.probing_width, args.min_probing_packets, args.scanning_width, args.min_scanning_packets)

    with open('part2_output.txt', 'w') as output_file:
        output_file.write("Reports of probing with TCP:\n")
        for src_ips, port, attempts in probing_reports_tcp:
            output_file.write(f">probing from {''.join(src_ips)} to port {port} - total attempts: {attempts}\n")
        
        output_file.write("\nReports of probing with UDP:\n")
        for src_ips, port, attempts in probing_reports_udp:
            output_file.write(f">probing from {''.join(src_ips)} to port {port} - total attempts: {attempts}\n")

        # Print reports of scanning with TCP
        output_file.write("\nReports of scanning with TCP:\n")
        for source_ip, attempts in scanning_reports_tcp:
            output_file.write(f">scanning from {source_ip} - total attempts: {attempts}\n")

        output_file.write("\nReports of scanning with UDP:\n")
        for source_ip, attempts in scanning_reports_udp:
            output_file.write(f">scanning from {source_ip} - total attempts: {attempts}\n")

if __name__ == "__main__":
    main()
