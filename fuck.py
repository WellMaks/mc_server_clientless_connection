from scapy.all import *
import numpy as np
import leb128


#Handshake
packet_id = 0 #hex
protocol_version = 759 #varint size 5
server_addr = "127.0.0.1" #string(255)
addr_size = len(server_addr.encode('utf-8'))
server_port = 25565 #unsigned short
next_state = 2 #varint 2 = login   1 = status

#Login Start
packet_login = 0
name = 'abc' #String(16) players username
name_length = len(name.encode('utf-8'))
has_sig_data = 0 #Bool  send next 5 fields?
# timestamp =    # optional / if sig data is true
# public_key_length =     # optional / same condition
# public_key =     # optional / same condition
# signature =   # optional / same condition   


packet1 = packet_id.to_bytes(1, 'little') + leb128.u.encode(protocol_version) + leb128.u.encode(addr_size) + bytes(server_addr, 'utf-8') + server_port.to_bytes(2, byteorder='little') + leb128.u.encode(next_state)
packet1_size = len(packet1)
p1 = leb128.u.encode(packet1_size) + packet1


packet2 = packet_login.to_bytes(1, 'little') + leb128.u.encode(name_length) + bytes(name, 'utf-8') + has_sig_data.to_bytes(1, 'little')
packet2_size = len(packet2)
p2 = leb128.u.encode(packet2_size) + packet2

# Packet = Length (VarInt) + PacketID (VarInt) + Data (Byte Array)
# 

# def getPacketId():
#     a = 0
#     totalPacket = b''
#     totalSize = 0
#     for i in range(1, 5):
#         totalPacket += s.recv(1)
#         tmp = leb128.u.decode(totalPacket)
#         print(tmp)
#         if (a == tmp):
#             break
#         a = tmp
#         totalSize += 1
#     totalSize += a
#     print('Incoming ' + str(a))
#     print('Total ' + str(totalSize))
#     print(totalPacket)
#     return a

def getPacketId():
    a = 0
    totalPacket = b''
    totalSize = 0
    for i in range(1, 5):
        totalPacket += s.recv(1)
        tmp = leb128.u.decode(totalPacket)
        print(tmp)
        if (a == tmp):
            break
        a = tmp
        totalSize += 1
    totalSize += a
    print('Incoming ' + str(a))
    print('Total ' + str(totalSize))
    print(totalPacket)
    return a


print("aaa" + str(packet1_size))


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1",25565))
    s.send(p1)
    s.send(p2)



    dick = s.recv(getPacketId())
    print("[+] Received Total")
except Exception as e:
    raise e

print(int.from_bytes(b'\x80', byteorder='big'))