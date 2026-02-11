import hashlib
import datetime
import json

Database = {};
container = [];

def getBytes(file):
	f = open(file, 'r')
	totalChar = f.read()
	totalChars = len(totalChar)
	p = open(file, 'rb')
	while totalChars > 4096:
		p = open(file, 'rb')
		bin = p.read(4096)
		container.append(bin)
		totalChars -= 4096
	if totalChars > 0 and totalChars < 4096:
		bin = p.read(4096)
		container.append(bin)

	finalSUM = ""
	for i in container:
		if len(finalSUM) == 0:
			finalSUM = i
		else:
			finalSUM += i;
	return finalSUM

def getHash(hash):
	hashObject = hashlib.sha256(hash)
	hex = hashObject.hexdigest()
	return hex

def Register():
	try:
		file = input("Enter the file you want to register in the hash: ")
		hash = getHash(getBytes(file))
		id = 1
		currentTime = datetime.datetime.now()
		with open("registry.json", "r") as p:
			Database = json.load(p)
		with open("registry.json", "r") as q:
			data = json.load(q)
			for i in data:
				if file != data[i]["file name"]:
					if id < 10:
						certNum = "ID-2026-" + "00" + str(id)
						id += 1
					elif id < 100:
						certNum = "ID-2026-" + "0" + str(id)
						id += 1
					elif id < 1000:
						certNum = "ID-2026-" + str(id)
						id += 1
					Database.update({certNum:{"hash (SHA256)":hash, "file name":file,"timestamp":str(currentTime)}})
				elif file == data[i]["file name"]:
					print("You have the file stored with the certificate ID. QUITTING!")
					return
		json_str = json.dumps(Database, indent=4)
		with open("registry.json", "w") as f:
			f.write(json_str)
			print("Here is your certificate ID. Please keep it safe!")
			print(certNum)
			return
	except json.JSONDecodeError:
		certNum = "ID-2026-000"
		Database = {}
		Database.update({certNum:{"hash (SHA256)":hash, "file name":file,"timestamp":str(currentTime)}})
		json_str = json.dumps(Database, indent=4)
		with open("registry.json", "w") as f:
			f.write(json_str)
			print("Here is your certificate ID. Please keep it safe!")
			print(certNum)
	except FileNotFoundError:
		certNum = "ID-2026-000"
		Database = {}
		Database.update({certNum:{"hash (SHA256)":hash, "file name":file,"timestamp":str(currentTime)}})
		json_str = json.dumps(Database, indent=4)
		with open("registry.json", "w") as f:
			f.write(json_str)
			print("Here is your certificate ID. Please keep it safe!")
			print(certNum)

def verify():
	certNum = input("Certificate Number: ")
	with open('registry.json', 'r') as p:
		data = json.load(p)
		for i in data:
			if certNum in i:
				break;
			else:
				return;
	fileName = input("File Name: ")
	with open ('registry.json', 'r') as p:
		data = json.load(p)
		for i in data:
			if certNum == i:
				if fileName == data[i]["file name"]:
					break
				else:
					return
	hash = getHash(getBytes(fileName))
	with open('registry.json', 'r') as h:
		data = json.load(h)
		for i in data:
			if data[i]["hash (SHA256)"] == hash:
				print("Data not corrupted")
				return
			else:
				print("Data is corrupted")
				print("Corrupted hash: " + hash)
				print("Original: " + data[i]["hash (SHA256)"])
				return
print("Document Fingerprinting tool")
print("""
Choose one of these options:
1. Check Hash of a file
2. Register the Hash of a file into a JSON file.
3. Verify the document integrity
""")
ask = int(input("Answer with numbers: "))
if ask == 1:
	file = input("Enter your file you want to check the hash: ")
	hash = getHash(getBytes(file))
	print(hash)
elif ask == 2:
	Register()

elif ask == 3:
	verify()
