#!/usr/bin/python3
#
# 
#
# juicy-php.py - Finding paths to phpinfo for aws keys or xdebug rce
#
# By @RandomRobbieBF && Edit-By @xElkomy
import requests, re, sys, codecs,time
from multiprocessing import Pool
from time import time as timer

def logo():
	banner=(f'''\033
\t ##########--By @RandomRobbieBF && Edit-By @xElkomy--#########
\t [Example]: python3 juicy-php-lists.py targets.txt ..!
''')
	print(banner)
	time.sleep(1)
	
logo()

list_targets = sys.argv[1]

try:
    with codecs.open(list_targets, mode='r', encoding='ascii', errors='ignore') as f:
        ooo = f.read().splitlines()
except IOError:
    pass
ooo = list((ooo))
    


def test_url(urls,path):
	newurl = ""+urls+"/"+path+""
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*",}
	try:
		response = session.get(newurl, headers=headers,verify=False,timeout=30)
		if response.status_code == 200:
			if "$_SERVER['SCRIPT_NAME']" in response.text:
				print("[+] Found PHPinfo for "+newurl+" [+]")
				if 'xdebug.remote_connect_back</td>' in response.text:
					print("[+] Xdebug Enabled Possible RCE [+]")
					text_file = open("xdebug.txt", "a")
					text_file.write(""+newurl+"\n")
					text_file.close()
					return True
				if 'AWS_SECRET' in response.text:
					print("[+] AWS Keys Exposed [+]")
					text_file = open("aws.txt", "a")
					text_file.write(""+newurl+"\n")
					text_file.close()
					return True
				if "nginx" and "FPM/FastCGI" and "PHP Version 7." in response.text:
					print("[+] Nginx / FPM - Look at possible rce https://github.com/neex/phuip-fpizdam [+]")
					text_file = open("fpm-rce.txt", "a")
					text_file.write(""+newurl+"\n")
					text_file.close()
					return True	
						
				if 'ImageMagick release date </td><td class="v">2016' in response.text:
					print("[+] Check Out CVE-2016-3714 RCE might be possible if you can upload an image. [+]")
					text_file = open("imagetrick.txt", "a")
					text_file.write(""+newurl+"\n")
					text_file.close()
					return True				
			else:
				print("[-] No Luck for "+path+" [-]")
		else:
			print("[-] No Luck for "+path+" [-]")
	except:
		print ("[-] Check Url might have Issues [-]")
		sys.exit(0)
			
			
def grab_paths(urls):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	try:
		response = session.get("https://gist.githubusercontent.com/RandomRobbieBF/ea5b4bb307fa6f73bb4714841883bfbe/raw/phpinfo.txt", headers=headers,verify=False, proxies=proxyDict)
		lines = response.text.strip().split('\n')
		for path in lines:
			loop = test_url(urls,path)
			if loop:
				break
	except:
		print("[-] Failed to obtain paths file [-]")
		sys.exit(0)
				
def starter():
    try:
        start = timer()
        pp = Pool(10)
        pr = pp.map(test_url, ooo,grab_paths)
        print('Time: ' + str(timer() - start) + ' seconds')
    except:
        pass


if starter() == 'main':
    starter()
    print('''\t-------------@RandomRobbieBF & @xElkomy-------------
\tBye :(''')
