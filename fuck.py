from scapy.all import *
import zlib
import leb128
from modules.varInt import varInt
import time
import struct
import json
from threading import Thread

#Handshake
packet_id = 0 #hex
protocol_version = varInt(759) #varint size 5
server_addr = "127.0.0.1" #string(255)
addr_size = varInt(len(server_addr.encode('utf-8'))) #varint
server_port = 25565 #unsigned short
next_state = varInt(2) #varint 2 = login   1 = status

#Login Start
packet_login = 0
name = 'abcd' #String(16) players username
name_length = varInt(len(name.encode('utf-8')))
has_sig_data = bool(0) #Bool  send next 5 fields?


# without compression
def createPacket(compressed, packetId, *argv):
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
    if (compressed):
        packetLen = len(packetContent) + 1
        packet = leb128.u.encode(packetLen) + b'\x00' + packetContent
    else:
        packetLen = len(packetContent) 
        packet = leb128.u.encode(packetLen) + packetContent

    # print("sending packet: " + str(packet) + "  with length of: " + str(packetLen) + " and id: " + str(packetId))
    return packet

p1 = createPacket(False, b'\x00', protocol_version, server_addr, server_port, next_state)
p2 = createPacket(False, b'\x00', name, has_sig_data)

def readVarInt():
    buffer = s.recv(1)
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
        buffer+=s.recv(1)
    # print("len: " + str(length))
    return value, length

def getPacket(encoded=False):

    readSize = readVarInt()

    if (encoded):
        dataSize = readVarInt()
        id = readVarInt()
        content = s.recv(readSize[0] - dataSize[1] - id[1])
        # print("Id: " + str(bytes(leb128.u.encode(id[0]))))
        # print("Content: " + str(content))
    else:
        id = readVarInt()
        content = s.recv(readSize[0] - id[1])
    #     print("Id: " + str(bytes(leb128.u.encode(id[0]))))
    #     print("Content: " + str(content))
    # print("")

    return bytes(leb128.u.encode(id[0])), content, bytes(leb128.u.encode(readSize[0]))
    
try:
    #Connect to Server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1",25565))
    #Handshake and Login Start
    s.send(p1)
    s.send(p2)
    #Login Packet
    getPacket(False)
    print("[+] Login successful")

except Exception as e:
    raise e

playerPosition = False
playerCords = []
#Get server spawnpoint and players current position
while(playerPosition == False):

    a = getPacket(True)
    if a[0] == b'\x36': 
        print("Synchronize player position: " + str(a[1]))
        playerCords = [struct.unpack('d', a[1][0:8][::-1])[0], struct.unpack('d', a[1][8:16][::-1])[0], struct.unpack('d', a[1][16:24][::-1])[0]]
        spawn = True

    if a[0] == b'\x4a': 
        val = int.from_bytes(a[1][:8], "big")
        x = val >> 38
        y = val & 0xFFF
        z = (val >> 12) & 0x3FFFFFF
        spawnCords = [x, y, z]
        playerPosition = True

print("spawdn cords from list: "+str(spawnCords))
print("current player position list: "+str(playerCords))


def runGame():
    while(True):
        try:
            a = getPacket(True)
            # print(a[0])
            if a[0] == b'\x1e':
                print("recived keep alive: " + str(a[1]))
                s.send(createPacket(True, b'\x11' + a[1])) # keep alive         

            if a[0] == b'\x36': 
                print("Synchronize player position: " + str(a[1]))
                # print("Teleport ID: " + str(a[1][33:-1]))
                time.sleep(0.1)
                s.send(createPacket(True, b'\x00' + a[1][33:-1]))
            # block entity data

            if a[0] == b'\x61':
                print("block: " + str(a[1]))

        except Exception as e:
            # print(e)
            break

# north = z + 1   south = z - 1   east =  x + 1   west = x - 1
# you can choose between spawnpoint or current player position when to begin movment
def movePlayer(list):
    a = 0
    x = list[0]
    y = list[1]
    z = list[2]
    # print("x: " + str(x) + "  y: " + str(y) + "   z: " + str(z))
    time.sleep(2)
    s.send(createPacket(True, b'\x13' + struct.pack('d', float(x))[::-1] + struct.pack('d', float(y))[::-1] + struct.pack('d', float(z))[::-1] + b'\x01'))
    f = open('moves.json')
    data = json.load(f)
    for i in data['moves']:
        time.sleep(2)
        if i['direction'] == 'north':
            z += float(i['spaces'])
        if i['direction'] == 'south':
            z -= i['spaces']
        if i['direction'] == 'east':
            x += i['spaces']
        if i['direction'] == 'west':
            x -= float(i['spaces'])
        s.send(createPacket(True, b'\x13' + struct.pack('d', float(x))[::-1] + struct.pack('d', float(y))[::-1] + struct.pack('d', float(z))[::-1] + b'\x01'))
        s.send(createPacket(True, b'\x01', varInt(a), ((int(x).to_bytes(26, "little", signed = True) & 0x3FFFFFF) << 38) | (int(z + 1).to_bytes(26, "little", signed = True) & 0x3FFFFFF) << 12) | (int(y).to_bytes(12, "little", signed = True) & 0xFFF))
        a+=1


if __name__ == '__main__':
    Thread(target = runGame).start()
    Thread(target = movePlayer, args = (playerCords,)).start()
