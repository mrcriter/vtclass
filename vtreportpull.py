#!/usr/bin/env python
#**********************************************************
#* This is a basic tool to pull json style reports from VirusTotal
#* using a public API key. I have this configured to only query
#* once every 16 seconds. VT allows for 4 API calls per 1 min
#* 
#* Usage:
#* create a file 'md5_list.txt' in this same directory with a 
#* list of MD5 hashes you'd like to pull json reports for
#* 
#* To do:
#* - add functionality to monitor folder for additional 
#*   md5_listX files for continuous running
#* - move check for end of file to before 15sec wait
#**********************************************************

import sys,os, time, threading,mmap, json
import urllib, urllib2, argparse, hashlib, re
from pprint import pprint

completed = open("md5_completed.txt","ab+") # open file / create file in case first run
completed.close()
if not os.path.exists('./reports'): #if path does not exist, create it
  os.makedirs('reports')

def getReport(md5):
  myapikey = 'XXXXXX' #insert API key here
  baseurl = 'https://www.virustotal.com/vtapi/v2/'
  param = {'resource':md5,'apikey':myapikey,'allinfo': '1'}
  url = baseurl + "file/report"
  data = urllib.urlencode(param)
  result = urllib2.urlopen(url,data)
  jdata =  json.loads(result.read())
  return jdata
    
def file_read_loop():
  count = 1
  while 1:
    if read_file() == 0:
      print "No new hashes. Exiting"
      quit()
    else:
      print str(count) + ": Report downloaded, waiting 15 sec to run again"
    start = time.time()
    while (time.time() - start) <= 16 and not e.isSet():
      time.sleep(1)
    if e.isSet():
      quit()
    count = count + 1

def read_file():
  print "reading file..."
  with open('md5_list.txt') as infile:
    for line in infile:
      md5 = line.strip('\n').upper()
      if search_file("md5_completed.txt",md5) == 0:
        it = getReport(md5)
        print md5 + " - Unknown"
        if it['response_code'] == 0:
          print md5 + " -- Not Found in VT"
          return 0
        jsondumpfile = open("./reports/VTDL" + md5 + ".json", "w")
        pprint(it, jsondumpfile)
        jsondumpfile.close()
        completed = open("md5_completed.txt","a")
        completed.write(md5+'\n')
        completed.close()
        outfile = open('md5_list.tmp','w')
        for line in infile:
          outfile.write(line)
        outfile.close()
        infile.close()
        os.remove('md5_list.txt')
        os.rename('md5_list.tmp','md5_list.txt')
        return 1
      print md5 + " - Found"
  print "No more hashes to check"
  infile.close()
  return 0

def search_file(file,string):
  f = open(file,'r+')
  if os.fstat(f.fileno()).st_size <= 0:
    return 0
  s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
  if s.find(string) != -1:
    return 1
  else:
    return 0
  
def _quit():
    print 'Exiting...'
    e.set()
    thread.join() #wait for the thread to finish
    root.quit()
    root.destroy()

thread = threading.Thread(target=file_read_loop, args=())
e = threading.Event()
thread.start()

print 'Press CTRL-C to interrupt'
while thread.isAlive():
    try: time.sleep(1) #wait 1 second, then go back and ask if thread is still alive
    except KeyboardInterrupt: #if ctrl-C is pressed within that second,
                              #catch the KeyboardInterrupt exception
        e.set() #set the flag that will kill the thread when it has finished
        print 'Exiting...'
        thread.join() #wait for the thread to finish
