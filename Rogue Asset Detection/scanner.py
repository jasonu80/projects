# Credit: https://github.com/LasCC/Network-Scanner/blob/master/main.py

# DCF and PCF handshake, how it works will help.
import ast
from getmac import get_mac_address as gma
import scapy.all as scapy
import socket
import time
import netifaces
from ipaddress import IPv4Network
import nmap
import json

# Create the authorised devices that are inside the system.
print("Welcome to Rogue Asset detector! Please choose one of the following options:")
print("""
1. Add Devices (a)
2. Overwrite Devices (O)
 """)
option = input(" ")
askNet = input("Please enter your IP address with the subnet (Ex: 192.168.0.1/24): ")
police = nmap.PortScanner()
print(police.scan(askNet, arguments='-n -sn -PR --packet-trace'))

currentDevices = {};
def addDevices():
	for i in police.all_hosts():
		if police[i].state() == 'up':
			if 'mac' in police[i]['addresses']:
				print("INFO")
				MAC = police[i]['addresses']['mac']
				print("MAC: " + MAC)
				if MAC in police[i]['vendor']:
					vendor = police[i]['vendor'][MAC]
					print("Vendor: " + vendor)
				else:
					vendor = "Unknown"
					print("Vendor: " + vendor)
				if police[i]['hostnames'][0]['name'] != '':
					hostname = police[i]['hostnames'][0]['name']
				else:
					hostname = "UNIX"
			else:
				MAC = gma()
				MAC = MAC.upper()
			ask = input("Do you want to allow the network " + i + " to be authorised in the network? (y/n)")
			if ask == "y":
				currentDevices.update({MAC:{"IP":i, "Vendor":vendor, "Hostname":hostname}})
def scan():
	for i in police.all_hosts():
		if police[i].state() == 'up':
			if 'mac' in police[i]['addresses']:
				MAC = police[i]['addresses']['mac']
				if MAC in police[i]['vendor']:
					vendor = police[i]['vendor'][MAC]
				else:
					vendor = "Unknown"
				if police[i]['hostnames'][0]['name'] != '':
					hostname = police[i]['hostnames'][0]['name']
				else:
					hostname = "UNIX"
			else:
				MAC = gma()
				MAC = MAC.upper()
			currentDevices.update({MAC:{"IP":i, "Vendor":vendor, "Hostname":hostname}})
	return currentDevices

if option == 'O':
	addDevices()
	with open("listOfCurrentDevices.txt", "w") as f:
		f.write(str(currentDevices))

elif option == 'a':
	with open("listOfCurrentDevices.txt", "r") as f:
		data = f.read()
		RealData = ast.literal_eval(data)
	scan()
	for i,j in currentDevices.items():
		if i not in data:
			print("Alert: New device detected!")
			susVendor = j["Vendor"]
			susIP = j["IP"]
			print("Vendor: " + susVendor)
			print("IP: " + susIP)
			ask = input("Do you want to add " + i + " to your network? (y/n)")
			if ask == 'y':
				RealData.update({i:{"IP":susIP, "Vendor":susVendor, "Hostname":j["Hostname"]}})
				p = str(RealData)
				with open("listOfCurrentDevices.txt", "w") as f:
					f.write(p)
			else:
				continue

# Detection will be added soon.






















#network = IPv4Network(askNet) # Enter your own Network and subnet here.
#ip_list = []
#packet_list = []
#for i in network:
#	ip_list.append(i.exploded)
#def scan():
#	for i in ip_list:
#		request = scapy.ARP(pdst=i)
#		broadcast = scapy.Ether("ff:ff:ff:ff:ff:ff")
#		packet = broadcast/request
#		arp_list = scapy.srp(packet, timeout=1, verbose=False)[0]
#		print(f"{request}")
#		print(f"{arp_list}")
#		for j in arp_list:
#	  		packet_dict = {"IP" : j[1].psrc, "MAC" : j[1].hwsrc}
#	  		packet_list.append(packet_dict)
#
#scan() # runs the first ARP Scan
#with open("listOfCurrentDevices.txt", "a") as f:
#	f.write(packet_list)

#time.sleep(300) # Check the network again after 5 minutes.

#with open("listOfCurrentDevices.txt") as f:
#	currentDevices = f.read();
#packet_list = []
#scan() # Perform the second ARP scan
