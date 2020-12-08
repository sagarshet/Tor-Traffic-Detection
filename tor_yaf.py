print('''
  _____               _____          __  __ _            ______     _            _   _             
 |_   _|             |_   _|        / _|/ _(_)           |  _  \\   | |          | | (_)            
   | | ___  _ __ ______| |_ __ __ _| |_| |_ _  ___ ______| | | |___| |_ ___  ___| |_ _  ___  _ __  
   | |/ _ \\| '__|______| | '__/ _` |  _|  _| |/ __|______| | | / _ \\ __/ _ \\/ __| __| |/ _ \\| '_ \\ 
   | | (_) | |         | | | | (_| | | | | | | (__       | |/ /  __/ ||  __/ (__| |_| | (_) | | | |
   \\_/\\___/|_|         \\_/_|  \\__,_|_| |_| |_|\\___|      |___/ \\___|\\__\\___|\\___|\\__|_|\\___/|_| |_|
                                                                                                   
	''')
print('Script for Detecting the Tor Traffic.')
print('By :- Sagar -- Vikas -- Shehzad.')
print('-------------------------------------------------------------------------------------------------------')

from urllib.request import Request, urlopen
import subprocess
import sys

# Fetching Tor IP from Internet which is updated every 30 mins.
request = Request("https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-nodes.lst",headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'})
tor_ip = urlopen(request).read()
with open("torip.txt","wb") as file:
	file.write(tor_ip)
	print("[+]Fetched Tor IP's from Internet")

# Getting the pcap file from command line arguements
if (len(sys.argv) < 2):
    print('[-]PCAP file not provided..Quitting')
    exit(1)
else:
    pcap_file = sys.argv[1]

# Creating Tor server IP addresses set.
try:
    subprocess.check_call('rwsetbuild torip.txt tor-servers.set',shell=True)
except subprocess.CalledProcessError:
    print('[-]Error ... file might be already present.')
except OSError:
	print('[-]Error ... file might be not be present.')

# Converting the pcap file to yaf file.
print('[+]Converting the pcap file to yaf file.')
print('-------------------------------------------')
try:
    subprocess.check_call(f'yaf --in {pcap_file} --out manual.yaf --filter="port 9001" --applabel --applabel-rules=/usr/local/etc/yafApplabelRules.conf --max-payload=4000 --plugin-name=/usr/local/lib/yaf/dpacketplugin.la --lock',shell=True)
except subprocess.CalledProcessError:
    print('[-]Error ...')
    exit()
except OSError:
	print('[-]Error ...')

# convert the YaF format file to an IPFIX formatted file.
print('[+]converting the YaF format file to an IPFIX formatted file.')
print('-------------------------------------------')
try:
    subprocess.check_call('rwipfix2silk --silk-output=manual.rw manual.yaf',shell=True)
except subprocess.CalledProcessError:
    print('[-]Error ...')
    exit()
except OSError:
	print('[-]Error ...')

# Using rwfilter query to filter query
print('[+]Filtering the Network flow')
print('-------------------------------------------')
try:
    subprocess.check_call('rwfilter --site-config-file=/usr/local/share/silk/generic-silk.conf --dipset=tor-servers.set --proto=0- --type=all --pass=manual.bin manual.rw',shell=True)
except subprocess.CalledProcessError:
    print('[-]Error ...')
    exit()
except OSError:
	print('[-]Error ...')


# Resolving the tor exit nodes.
print('[+]Resolving Tor tertiary domain names')
print('-------------------------------------------')
try:
    subprocess.check_call('rwcut manual.bin |rwresolve',shell=True)
except subprocess.CalledProcessError:
    print('[-]Error ...')
    exit()
except OSError:
	print('[-]Error ...')

# Cleaning up .....
subprocess.check_call('rm manual.yaf',shell=True)
subprocess.check_call('rm manual.rw',shell=True)
subprocess.check_call('rm manual.bin',shell=True)
subprocess.check_call('rm tor-servers.set',shell=True)


