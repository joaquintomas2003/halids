from scapy.all import sniff, Raw

def handle(pkt):
    print("Packet received from NIC")

sniff(iface="vf0_0", prn=handle, store=0)
