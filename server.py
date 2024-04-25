from scapy.all import TCP, IP, send, sr1, sniff, Raw 

SERVER_PORT = 20000
CLIENT_PORT = 20001

def find_packet(packet):
    return TCP in packet and packet[TCP].dport == SERVER_PORT


def main():
    acknowledge = 0
    sequence = 2000

    syn_packet = sniff(count = 1, lfilter = find_packet)[0]
    syn_packet.show()

    acknowledge = syn_packet[TCP].seq + 1
    syn_ack_packet = IP(dst = '192.168.68.65')/TCP(sport = SERVER_PORT, dport = CLIENT_PORT, seq = sequence, ack = acknowledge, flags = 18)
    syn_ack_packet.show()
    
    ack_packet = sr1(syn_ack_packet)
    ack_packet.show()
    acknowledge = ack_packet[TCP].seq
    sequence = ack_packet[TCP].ack

    client_packet = sniff(count = 1, lfilter = find_packet)[0]

    acknowledge = client_packet[TCP].seq + len(client_packet[Raw].load)
    sequence = client_packet[TCP].ack

    server_packet = IP(dst = '192.168.68.65')/TCP(sport = SERVER_PORT, dport = CLIENT_PORT, seq = sequence, ack = acknowledge, flags = 16)/Raw("Hello to you")
    client_packet = sr1(server_packet)

    acknowledge = client_packet[TCP].seq + len(client_packet[Raw].load)
    sequence = client_packet[TCP].ack

    server_packet = IP(dst = '192.168.68.65')/TCP(sport = SERVER_PORT, dport = CLIENT_PORT, seq = sequence, ack = acknowledge, flags = 16)/Raw("I am fine!")
    client_packet = sr1(server_packet)

    acknowledge = client_packet[TCP].seq
    sequence = client_packet[TCP].ack
   
if __name__ == "__main__":
    main()