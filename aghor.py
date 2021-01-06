import yara
import sys
import hashlib
from termcolor import colored
import pyfiglet
import time
from tqdm import tqdm


ascii_banner = pyfiglet.figlet_format("aghor")
print(ascii_banner)


animation = "|/-\\"

for i in range(50):
    time.sleep(0.1)
    sys.stdout.write("\r Scanning your file...." + animation[i % len(animation)])
    sys.stdout.flush()
   

rule = yara.compile(filepath="Rule_DB.yara")

  
matches = rule.match(sys.argv[1],  timeout=60)
for i in tqdm(range(10)):
	time.sleep(0.9)

print("\n")

if matches:
	print colored('MALWARE', 'red' ,  attrs=['bold'])

else:
    print colored('CLEAN', 'green',  attrs=['bold'])

matches = hashlib.md5(sys.argv[1]).hexdigest()
print(('MD5 =') + matches)
time.sleep(0.05)
print("\n")
print colored("Scan Completed...!!", "yellow")
