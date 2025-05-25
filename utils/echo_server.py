from scapy.all import sniff, sendp, Ether, IP
import argparse

def echo_packet(packet):
    if Ether in packet:
        ether = packet[Ether]
        # Swap source and destination MAC
        ether.src, ether.dst = ether.dst, ether.src

        if IP in packet:
            ip = packet[IP]
            # Swap source and destination IP
            ip.src, ip.dst = ip.dst, ip.src
            print(f"Echoing IP packet: {ip.src} -> {ip.dst}")
        else:
            print("Echoing non-IP Ethernet frame.")

        # Send the modified packet back
        sendp(ether / packet.payload, iface=args.interface, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="Echo Server")
    parser.add_argument("-i", "--interface", required=True, help="Interface to listen on (e.g., eth0)")
    global args
    args = parser.parse_args()

    print(f"[*] Listening on interface: {args.interface}")
    sniff(iface=args.interface, prn=echo_packet, store=0)

if __name__ == "__main__":
    main()
