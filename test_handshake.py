import hashlib
import hmac

from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.eap import EAPOL_KEY, EAPOL
from scapy.utils import rdpcap

packets = rdpcap("data/capture-01.cap")
bssid_find = "66:4b:93:37:28:0f"

bssid=None
ssid = None
sta = None
anonce = None
snonce = None
wpadata = None
reference_mic = None

#  it is fix methode in EAPOL_KEY.guess_key_number in scapy==2.6.1
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
    if bssid_find.lower() in [packet.addr1, packet.addr2, packet.addr3]:
        if packet.haslayer(EAPOL_KEY):
            p = packet[EAPOL_KEY]
            message_n = guess_key_number(p)

            if message_n == 1: #  Key Information: 0x008a
                bssid = bytes.fromhex(packet.addr2.replace(":", ""))
                sta = bytes.fromhex(packet.addr1.replace(":", ""))
                anonce = p.key_nonce
                print("bssid: "+bssid.hex())
                print("sta: "+sta.hex())
                print("aNonce: " + anonce.hex())

            elif message_n == 2: #  Key Information: 0x010a
                snonce = p.key_nonce
                reference_mic = p.key_mic.hex()
                print("sNonce: " + snonce.hex())
                print("mic: " + reference_mic)
                #  802.1X Authentication
                wpadata = bytearray(bytes(packet[EAPOL]))
                wpadata[81:97] = b'\x00' * 16 #  удаляем из EAPOL код целостности mic
                print("wpaData: " + wpadata.hex())

        elif packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Beacon].info
            print("ssid: " + ssid.decode("utf-8"))



test_password = input("\nTest password: ")

#  генерация Pairwise Master Key
pmk = hashlib.pbkdf2_hmac('sha1', test_password.encode('utf-8'), ssid, 4096, 32)
print("Pairwise Master Key: " + pmk.hex())

#  генератор Pairwise Transport Key
def calc_ptk(key, data):
    blen = 64
    i = 0
    ret = b""

    while i<=((blen*8+159) /160):
        hmacsha1 = hmac.new(key, b'Pairwise key expansion\x00' + data + chr(i).encode(), hashlib.sha1)
        i += 1
        ret = ret + hmacsha1.digest()

    return ret[:blen]

#  генерация Pairwise Transport Key
key_data = min(bssid, sta) + max(bssid, sta) + min(anonce, snonce) + max(anonce, snonce)
ptk = calc_ptk(pmk, key_data)
print("Pairwise Transport Key: " + ptk.hex())

#  генерация Message Integrity Code
mic = hmac.new(ptk[0:16], wpadata, "sha1")
print("Generated MIC: " + mic.hexdigest()[:-8])

if mic.hexdigest()[:-8] == reference_mic:
    print('\nMIC matched')
else:
    print('\nMIC didn`t match')
