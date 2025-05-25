from scapy.all import sniff, sendp, Ether, IP
import argparse

MTU = 1500

def echo_packet(packet):
    if Ether in packet:
        eth = packet[Ether]
        if IP in packet:
            ip = packet[IP]

            # Build new layers by reversing src/dst
            ether = Ether(src=eth.dst, dst=eth.src)
            ip_layer = IP(src=ip.dst, dst=ip.src)
            payload = bytes(ip.payload)

            total_len = len(ether) + len(ip_layer) + len(payload)

            if total_len > MTU:
                print(f"Skipping oversized packet: {total_len} bytes")
                return

            response = ether / ip_layer / payload
            print(f"Echoing IP packet: {ip.src} -> {ip.dst} (size {total_len})")
            sendp(response, iface=args.interface, verbose=False)
        else:
            print("Non-IP packet, not echoed.")

def main():
    parser = argparse.ArgumentParser(description="Echo Server")
    parser.add_argument("-i", "--interface", required=True, help="Interface to listen on (e.g., eth0)")
    global args
    args = parser.parse_args()

    print(f"[*] Listening on interface: {args.interface}")
    sniff(iface=args.interface, prn=echo_packet, store=0)

if __name__ == "__main__":
    main()
