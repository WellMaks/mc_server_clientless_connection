from scapy.all import *
import zlib
import leb128
from modules.varInt import varInt
import time

#Handshake
packet_id = 0 #hex
protocol_version = varInt(759) #varint size 5
server_addr = "127.0.0.1" #string(255)
addr_size = varInt(len(server_addr.encode('utf-8'))) #varint
server_port = 25565 #unsigned short
next_state = varInt(2) #varint 2 = login   1 = status

#Login Start
packet_login = 0
name = 'abc' #String(16) players username
name_length = varInt(len(name.encode('utf-8')))
has_sig_data = bool(0) #Bool  send next 5 fields?


# without compression
def createPacket(packetId, *argv):
    packetContent = packetId
    for arg in argv:
        if isinstance(arg, bool):
            arg = arg.to_bytes(1, 'little')
        elif isinstance(arg, int):
            arg = arg.to_bytes(2, 'little')
        if isinstance(arg, varInt):
            arg = bytes(arg)
        if isinstance(arg, str):
            content = bytes(arg, 'utf-8')
            contentLen = len(arg)
            arg = bytes(varInt(contentLen)) + content

            
        packetContent += arg
    packetLen = len(packetContent) 
    packet = leb128.u.encode(packetLen) + packetContent

    # print("sending packet: " + str(packet) + "  with length of: " + str(packetLen) + " and id: " + str(packetId))
    return packet

p1 = createPacket(b'\x00', protocol_version, server_addr, server_port, next_state)
p2 = createPacket(b'\x00', name, has_sig_data)


# def getPacketId():
#     incomingPacket = 0
#     totalPacket = b''
#     totalSize = 0
#     for i in range(1, 5):
#         totalPacket += s.recv(1)
#         tmp = leb128.u.decode(totalPacket)
#         if (incomingPacket == tmp):
#             break
#         incomingPacket = tmp
#         totalSize += 1
#     totalSize += incomingPacket
#     # print('Incoming ' + str(incomingPacket))
#     # print('Total ' + str(totalSize))
#     # print(totalPacket)
#     return incomingPacket


def getPacketId():
    size = 0
    id = 0
    packetSize = b''
    packetId = b''
    totalSize = 0

    for i in range(1, 5):
        packetSize += s.recv(1)
        tmp = leb128.u.decode(packetSize)
        print("a:" + str(tmp))
        if (size == tmp):
            break  
        size = tmp
        # totalSize += 1
    totalSize += size

    for j in range(1, 5):
        packetId += s.recv(1)
        tmp = leb128.u.decode(packetId)
        print("b:" + str(tmp))
        if (id == tmp):
            break
        id = tmp
    print("")
    print("================")
    print("")
    print("ID: " + str(packetId))
    print("Size: " + str(packetSize) + " (" + str(int.from_bytes(packetSize, "little")) + ")")
    print('Total Size: ' + str(totalSize))
    print("")
    return totalSize

try:
    #Connect to Server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1",25565))
    #Handshake and Login Start
    s.send(p1)
    s.send(p2)

    #Login Packet
    packet3 = s.recv(getPacketId())
    print(packet3)
    print("[+] Received Total")
    print(s.recv(getPacketId()))
    print(s.recv(getPacketId()))
    print(s.recv(getPacketId()))


except Exception as e:
    raise e



# while True:

#     a = s.recv(getPacketId())
#     try:
#         if hex(a[0]) == hex(0x1e):
#             print("found!")
#             print("recived: " + str(a))
#             # time.sleep(4)
#             s.send(createPacket(b'\x07',b'\x11', a[1:]))
#             # try:
#             #     b = createPacket(b'\x11', b'\x00')
#             #     print(b)
#             #     s.send(b)
#             # except Exception as e:
#             #     print(e)  

#     except Exception as e:
#         pass