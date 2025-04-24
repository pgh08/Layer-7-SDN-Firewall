# from scapy.all import *

# def packet_handler(packet):
#     if packet.haslayer(Raw):
#         print("Received:", packet[Raw].load.decode('utf-8'))
#         pkt = IP(dst="192.168.1.2", src='10.0.0.1')/TCP(flags='SA')/Raw(load="Hello, from server!")
#         send(pkt)

# # Sniffing packets on the server
# sniff(filter="tcp and host 192.168.1.2 and port 12345", prn=packet_handler)

from socket import *

serverName= "10.0.0.5"
serverPort = 12000

serverSocket = socket(AF_INET,SOCK_STREAM)
serverSocket.bind((serverName,serverPort))
serverSocket.listen(1)
print ("The server is ready to receive")
connectionSocket, addr = serverSocket.accept()
print("Connected to client : ", addr)

while 1:
    sentence = connectionSocket.recv(1024).decode()
    print("From Client : ", sentence)
    msg = input("Reply : ")
    connectionSocket.send(msg.encode())
connectionSocket.close()