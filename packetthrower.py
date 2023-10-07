import scapy.all as scapy

interface = "wlp0s20f3"

ip_packet = scapy.IP(dst="10.12.10.43")

tcp_packet = scapy.TCP(dport=80)

udp_packet = scapy.UDP(dport=80)
print("IP Packet Summary: ", ip_packet.summary())
print("\n")
print("For TCP:")
print("TCP Packet Summary: ", tcp_packet.summary())

packet = ip_packet/tcp_packet

print("TCP/IP Packet Summary: ", packet.summary())

response = scapy.sr1(packet, iface=interface)

if response:
    print("Response: ", response.summary())
    send_time = packet.sent_time
    receive_time = scapy.time.time()
    latency = receive_time - send_time
    speed = len(packet) / latency
else:
    print("No response")

print("Packet Length: ", len(packet))
print(f"Latency: {latency} seconds")
print(f"Speed: {speed} bytes/second")
print("\n")

print("For UDP:")
packet = ip_packet/udp_packet
scapy.send(packet, iface=interface)
print("UDP Packet Summary: ", udp_packet.summary())
print("Packet Length: ", len(packet))
print("\n")

print("For QUIC:")
quic_packet = ip_packet / udp_packet / b"payload"

scapy.send(quic_packet, iface=interface)
print("QUIC Packet Summary: ", quic_packet.summary())
print("Packet Length: ", len(quic_packet))
print("\n")

print("For ICMP:")
icmp_packet = scapy.IP(dst="10.12.10.43") / scapy.ICMP()

response = scapy.sr1(icmp_packet)

if response:
    latency = response.time - icmp_packet.time
    print(f"Latency: {latency} seconds")
    ttl = response.ttl
    print(f"TTL: {ttl}")
    print("Response: ", response.summary())
    print("Packet Length: ", len(response))
    print("\n")
else:
    print("No response received.")
    