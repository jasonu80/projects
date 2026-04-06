# Credit: https://github.com/LasCC/Network-Scanner/blob/master/main.py

# DCF and PCF handshake, how it works will help.
from getmac import get_mac_address as gma
import nmap
import json
import time

# Create the authorised devices that are inside the system.
print("Welcome to Rogue Asset detector.")
askNet = input("Please enter your IP address with the subnet (Ex: 192.168.0.1/24): ")
police = nmap.PortScanner()
print(police.scan(askNet, arguments='-n -sn -PR --packet-trace'))

currentDevices = {};
def addDevices(): # Add and scan.
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

def convertToJSON(file):
	with open("devices.json", "w") as f:
		json.dump(file, f, indent=4)

def optionN():
	addDevices()
	convertToJSON(currentDevices)

def optionA():
	with open("devices.json", "r") as f:
		RealData = json.load(f)
	scan()
	for i,j in currentDevices.items():
		if i not in RealData:
			print("Alert: New device detected!")
			susVendor = j["Vendor"]
			susIP = j["IP"]
			print("Vendor: " + susVendor)
			print("IP: " + susIP)
			ask = input("Do you want to add " + i + " to your network? (y/n)")
			if ask == 'y':
				RealData.update({i:{"IP":susIP, "Vendor":susVendor, "Hostname":j["Hostname"]}})
				convertToJSON(RealData)
			else:
				continue
print("""
	  Choose one of these options:
1. Add & Detect new devices (A)
2. Create New List Devices (N)
 """)
option = input(" ")
if option == 'N':
	optionN()

elif option == 'A':
	optionA()

print("Please wait 5 minutes for the next scan.")
while True:
	time.sleep(300)
	optionA()

