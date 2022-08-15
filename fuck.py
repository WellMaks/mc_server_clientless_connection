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

def readVarInt(buffer):
    value = 0
    length = 0
    currentByte = b''

    while(True):
        currentByte = buffer[length]
        value |= (currentByte & 0x7f) << (length * 7)
        length += 1
        if(length > 5):
            print("VarInt too long")
        if(currentByte & 0x80) != 0x80:
            break
    # print("len: " + str(length))
    return value, length

def getPacket(encoded=False):

    buffer = s.recv(1)  #packet size
    lenBuffer = 1

    for i in range(1, 4):
        buffer += s.recv(1)
        result = readVarInt(buffer)
        temp = result[1]
        if(lenBuffer == temp):
            break
        lenBuffer = temp
    contentSize = int(result[0]) - 1
    packetContentRecived = s.recv(contentSize)
    packetContent = bytearray(buffer[-1:]) + bytearray(packetContentRecived) 

    # print("")
    # print("Packet Size: " + str(buffer[:-1]))

    if (encoded):
        dataSize = readVarInt(packetContent)
        id = readVarInt(packetContent[dataSize[1]:])
        id2 = bytes(leb128.u.encode(id[0]))
        content = bytes(packetContent[id[1]+dataSize[1]:])
        # print("Data Size: " + str(bytes(leb128.u.encode(dataSize[0]))))
        # print("Id: " + str(id2))
        # print("Content: " + str(content))
    else:
        id = readVarInt(packetContent)
        id2 = bytes(leb128.u.encode(id[0]))
        content = bytes(packetContent[id[1]:])
        # print("Id: " + str(id2))
        # print("Content: " + str(content))
    # print("")
    return id2, content


try:
    #Connect to Server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1",25565))
    #Handshake and Login Start
    s.send(p1)
    s.send(p2)

    #Login Packet

    getPacket(False)
    getPacket(False)
    print("[+] Received Total")


except Exception as e:
    raise e



while (True):
    try:
        a = getPacket(True)
        # print(a[0])
        if a[0] == b'\x1e':
            print("found!")
            print("recived: " + str(a[1]))
            time.sleep(2)
            s.send(createPacket(b'\x08',b'\x11', a[1]))


    except Exception as e:
        pass