from scapy.all import TCP, IP, send, sr1, Raw

SERVER_PORT = 20000
CLIENT_PORT = 20001

def main():
    acknowledge = 0
    sequence = 123

    syn_segment = IP(dst = '192.168.68.65')/TCP(sport = CLIENT_PORT, dport = SERVER_PORT, seq = sequence, flags = 2)
    syn_segment.show()
    
    syn_ack_packet = sr1(syn_segment)
    syn_ack_packet.show()
    sequence = syn_ack_packet[TCP].ack
    acknowledge = syn_ack_packet[TCP].seq + 1
    
    ack_segment = IP(dst = '192.168.68.65')/TCP(sport = CLIENT_PORT, dport = SERVER_PORT, seq = sequence, ack = acknowledge, flags = 16)
    ack_segment.show()
    send(ack_segment)

    client_packet = IP(dst = '192.168.68.65')/TCP(sport = SERVER_PORT, dport = CLIENT_PORT, seq = sequence, ack = acknowledge, flags = 16)/Raw("Hello")
    server_packet = sr1(client_packet)

    acknowledge = server_packet[TCP].seq + len(client_packet[Raw].load)
    sequence = server_packet[TCP].ack
    
    client_packet = IP(dst = '192.168.68.65')/TCP(sport = SERVER_PORT, dport = CLIENT_PORT, seq = sequence, ack = acknowledge, flags = 16)/Raw("How are you?")
    server_packet = sr1(client_packet)
    
    acknowledge = server_packet[TCP].seq + len(client_packet[Raw].load)
    sequence = server_packet[TCP].ack
    
    client_packet = IP(dst = '192.168.68.65')/TCP(sport = SERVER_PORT, dport = CLIENT_PORT, seq = sequence, ack = acknowledge, flags = 16)
    send(client_packet)
         
if __name__ == "__main__":
    main()