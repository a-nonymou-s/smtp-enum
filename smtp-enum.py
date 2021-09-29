#!usr/bin/python3
import sys
import socket
if len(sys.argv) !=3 :
	print("[*] Usage ./smtp-enum.py <ip> <user file>")
	exit(0)
for file in sys.argv[2]:
	ip = sys.argv[1]
	user = file
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	connect = s.connect((ip,25))
	banner = s.recv(1024)

	print(banner)

	s.send("VRFY " + user +'\r\n')
	result = s.recv(1024)
	print(result)
	s.close()
