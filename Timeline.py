import sys
import csv
import os
import re
import datetime

file_list = []
head = ['Timestamp (UTC)', 'Activity', 'Details']
det = []

directory = sys.argv[1]

for r, d, f in os.walk(directory):
	for fil in f:
		if '.csv' in fil:
			file_list.append(os.path.join(r, fil))

for file in file_list:
	if "Evtx" in file:
		with open(file , 'r', encoding="utf-8") as f:
			file_dict = csv.DictReader(f)
			for line in file_dict:
				if line['EventId'] == '1149':
					deets = 'EventID: %s | Username: %s | Source IP: %s' % (line['EventId'], line['UserName'], line['RemoteHost'])
					evt = [line['TimeCreated'], 'Incoming RDP', deets]
					det.append(evt)

				if line['EventId'] == '7045':
					deets = 'EventID: %s | %s | Image Path: %s | %s' % (line['EventId'], line['PayloadData1'], line['ExecutableInfo'], line['PayloadData2'])
					evt = [line['TimeCreated'], 'Service installed', deets]
					det.append(evt)

				else:
					src = re.search('logs\\\\(.+?).evtx', line['SourceFile'])
					deets = 'Event ID: %s | Event Payload: %s' % (line['EventId'], line['Payload']) + ' | Source File: %s' % src.group(1)
					evt = [line['TimeCreated'], 'Event log', deets]
					det.append(evt)


	if "Amcache" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				deets = 'Full path: %s | SHA1: %s | File Desc: %s | Prod Name: %s | Company Name: %s' % (line['FullPath'], line['SHA1'], line['FileDescription'], line['ProductName'], line['CompanyName'])
				evt = [line['FileIDLastWriteTimestamp'], 'Amcache', deets]
				det.append(evt)

	if "AppResourceUseInfo" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				deets = 'Exe info: %s | Username: %s | SID: %s' % (line['ExeInfo'], line['UserName'], line['Sid'])
				evt = [line['Timestamp'], 'SRUM - App Usage', deets]
				det.append(evt)

	if "NetworkUsages" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				deets = 'Exe info: %s | Username: %s | SID: %s | Bytes Received: %s | Bytes Sent: %s' % (line['ExeInfo'], line['UserName'], line['Sid'], line['BytesReceived'], line['BytesSent'])
				evt = [line['Timestamp'], 'SRUM - NW Usage', deets]
				det.append(evt)

	if "PECmd_Output_Timeline" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				deets = 'Exe Name: %s' % (line['ExecutableName'])
				evt = [line['RunTime'], 'Prefetch', deets]
				det.append(evt)

	if "AppCompatCache" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				deets = 'Exe Path: %s' % (line['Path'])
				evt = [line['LastModifiedTimeUTC'], 'Shimcache', deets]
				det.append(evt)

	if "UserAssist" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				user = re.search('Users_(.+?)_NTUSER', file)
				deets = 'Program Name: %s | Run Counter: %s | Focus Count: %s' % (line['ProgramName'], line['RunCounter'], line['FocusCount']) + ' | User: %s' % user.group(1)
				evt = [line['LastExecuted'], 'UserAssist', deets]
				det.append(evt)

	if "Services" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				user = re.search('Users_(.+?)_NTUSER', file)
				deets = 'Image path: %s | Service DLL: %s | Name: %s | Start mode: %s' % (line['ImagePath'], line['ServiceDLL'], line['\ufeffName'], line['StartMode'])
				evt = [line['NameKeyLastWrite'], 'Service - Registry', deets]
				det.append(evt)

	if "TerminalServerClient" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				user = re.search('Users_(.+?)_NTUSER', file)
				deets = 'Dest IP: %s | Dest User: %s' % (line['\ufeffHostName'], line['Username']) + ' | User: %s' % user.group(1)
				evt = [line['LastModified'], 'Terminal Server Client', deets]
				det.append(evt)

	if "LECmd" in file:
		with open(file, 'r', encoding="utf-8") as g:
			gile_dict = csv.DictReader(g)
			for line in gile_dict:
				deets = 'Local Path: %s | NW Path: %s | Common Path: %s | TargetAbsolutePath: %s' % (line['LocalPath'], line['NetworkPath'], line['CommonPath'], line['TargetIDAbsolutePath'])
				evt = [line['TargetCreated'], 'LNK Taget Created', deets]
				det.append(evt)
				deets = 'Local Path: %s | NW Path: %s | Common Path: %s | TargetAbsolutePath: %s' % (line['LocalPath'], line['NetworkPath'], line['CommonPath'], line['TargetIDAbsolutePath'])
				evt = [line['TargetModified'], 'LNK Taget Modified', deets]
				det.append(evt)
				deets = 'Local Path: %s | NW Path: %s | Common Path: %s | TargetAbsolutePath: %s' % (line['LocalPath'], line['NetworkPath'], line['CommonPath'], line['TargetIDAbsolutePath'])
				evt = [line['TargetAccessed'], 'LNK Taget Accessed', deets]
				det.append(evt)

time = datetime.datetime.now()
timestamp = str(time.year)+str(time.month)+str(time.day)+str(time.hour)+str(time.minute)+str(time.second)


with open(sys.argv[2]+"\\" + timestamp + "_" + "Timeline.csv", 'w', encoding="utf-8") as wr:
	csvwriter = csv.writer(wr)
	csvwriter.writerow(head)
	csvwriter.writerows(det)

