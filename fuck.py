from scapy.all import *
import zlib
import leb128
from modules.varInt import varInt

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
# timestamp =    # optional / if sig data is true
# public_key_length =     # optional / same condition
# public_key =     # optional / same condition
# signature =   # optional / same condition   

# without compression
def createPacket(*argv):
    packetContent = b'\x00'
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
    return packet

p1 = createPacket(protocol_version, server_addr, server_port, next_state)
p2 = createPacket(name, has_sig_data)

def getPacketId():
    incomingPacket = 0
    totalPacket = b''
    totalSize = 0
    for i in range(1, 5):
        totalPacket += s.recv(1)
        tmp = leb128.u.decode(totalPacket)
        if (incomingPacket == tmp):
            break
        incomingPacket = tmp
        totalSize += 1
    totalSize += incomingPacket
    print('Incoming ' + str(incomingPacket))
    print('Total ' + str(totalSize))
    print(totalPacket)
    return incomingPacket



try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1",25565))
    s.send(p1)
    s.send(p2)



    packet3 = s.recv(getPacketId())
    print(packet3)
    print(hex(packet3[0]))
    print("[+] Received Total")
except Exception as e:
    raise e

# found = False

# keep alive to fix
while True:
    a =s.recv(getPacketId())
    try:
        if hex(a[0]) == hex(0x1E):
            keepAliveData = b'\x11' + a[1:]
            keepAlive = leb128.u.encode(len(keepAliveData)) + leb128.u.encode(len(a[1:])) + zlib.compress(leb128.u.encode(hex(0x11))) + zlib.compress(a[1:])

            # s.send(keepAlive)
            break

    except Exception as e:
        print(e)


