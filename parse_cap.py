from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.eap import EAPOL_KEY
from scapy.utils import rdpcap

packets = rdpcap("data/capture-01.cap")
bssid = "66:4b:93:37:28:0f"

# it is fix methode in EAPOL_KEY.guess_key_number in scapy==2.6.1
def guess_key_number(pckt):
    if pckt.key_type == 1:
        if pckt.key_ack == 1:
            if pckt.has_key_mic == 0:
                return 1
            if pckt.install == 1:
                return 3
        else:
            if pckt.secure == 0:
                return 2
            return 4
    return 0

for packet in packets:
    if bssid.lower() in [packet.addr1, packet.addr2, packet.addr3]:
        if packet.haslayer(EAPOL_KEY):
            p = packet[EAPOL_KEY]
            message_n = guess_key_number(p)

            if message_n == 1: #  Key Information: 0x008a
                print("bssid: "+packet.addr2)
                print("sta: "+packet.addr1)
                print("aNonce: " + p.key_nonce.hex())

            elif message_n == 2: #  Key Information: 0x010a
                print("sNonce: " + p.key_nonce.hex())
                print("mic: " + p.key_mic.hex())
                #  802.1X Authentication
                wpadata = bytearray(bytes(p))
                wpadata[76:93] = b'\x00' * 16 # удаляем из EAPOL код целостности mic
                print("wpaData: " + wpadata.hex())

        elif packet.haslayer(Dot11Beacon):
            print("ssid: " + packet[Dot11Beacon].info.decode("utf-8"))
