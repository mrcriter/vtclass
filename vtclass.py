#!/usr/bin/python
# I stole this from the internet, it's free!!!
# special thanks to Xen0ph0n (https://github.com/Xen0ph0n)

import json, urllib, urllib2, argparse, hashlib, re, sys
from pprint import pprint
import operator
from collections import Counter
import string


class vtAPI():
    def __init__(self):
        self.api = '' #insert API key here
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    
    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api,'allinfo': '1'}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata
    
# Md5 Function

def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else: 
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 
          
def parse(it, md5, verbose, jsondump, classify):
  if it['response_code'] == 0:
    print md5 + " -- Not Found in VT"
    return 0
  print "\n\tResults for MD5: ",it['md5'],"\n\n\tDetected by: ",it['positives'],'/',it['total'],'\n\tScanned on:',it['scan_date'],'\n\tsha256:',it['sha256']

  if jsondump == True:
    jsondumpfile = open("VTDL" + md5 + ".json", "w")
    pprint(it, jsondumpfile)
    jsondumpfile.close()
    print "\n\tJSON Written to File -- " + "VTDL" + md5 + ".json"

  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']

  if classify == True:
    count_all = Counter()
    results = []
    for x in it['scans']:
      if it['scans'][x]['detected'] == True:
        temp_result = x.encode('UTF8'),normalize(str(it['scans'][x]['result'].encode('UTF8'))),score(x.encode('UTF8'))
        print temp_result
        results.append(temp_result)
    #print results
    counts = Counter(results)
    #print(counts)
    #rx = '[' + re.escape(''.join(extra)) + ']'
    #final_ready = re.sub(rx,' ', results).replace('  ',' ')
    #final = Counter(final_ready.split())
    #print 'Guess: ', list(dict((k,v) for k,v in final.iteritems() if v > it['positives']/2).keys())
    #print 'All results: ', final

def normalize(input):
  output = re.sub('adware','Adware',input,flags=re.I)
  output = re.sub('backdoor','Backdoor',output,flags=re.I)
  output = re.sub('worm','Worm',output,flags=re.I)
  output = re.sub('trojan','Trojan',output,flags=re.I)
  output = re.sub('hacktool','HackTool',output,flags=re.I)
  output = output.replace('I-Worm.','Worm:').replace('W32','Win32').replace('BehavesLike.','')
  output = output.replace('-gen','/Generic')
  output = output.replace('Win32:','Win32/')
  output = output.replace('PE.','').replace('PE:','').replace('PE_','')
  output = output.replace('Adware/','Adware:').replace('Adware.','Adware:')
  output = output.replace('Virus/','Virus:').replace('Virus.','Virus:')
  output = output.replace('Worm/','Worm:').replace('Worm.','Worm:').replace('Worm_','Worm:')
  output = output.replace('Trojan/','Trojan:').replace('Trojan.','Trojan:')
  output = output.replace('Backdoor/','Backdoor:').replace('Backdoor.','Backdoor:')
  output = output.replace('Win32/Adware:','Adware:Win32/')
  output = output.replace('Win32/Trojan:','Trojan:Win32/')
  output = output.replace('Win32/Virus:','Virus:Win32/')
  output = output.replace('Win32/Backdoor:','Backdoor:Win32/')
  output = output.replace('Win32.','Win32/')
  output = output.replace('not-a-virus:','')
  output = output.replace('a variant of ','')
  if re.match("\.Worm'", output):
     output = output.replace(".Worm","").replace(" \'","Worm:")
  if re.match("\.Trojan'", output):
     output = output.replace(".Trojan","").replace(" \'","Trojan:")
  output = output.replace(':.',':')

  return output

def score(input):
  av_scores = {"ALYac": .5, "Ad-Aware": .5, "AegisLab": .5, "Agnitum": .5, "AhnLab-V3": .5, \
               "Alibaba": .5, "Antiy-AVL": .5, "Arcabit": .5, "Avast": .5, "AVG": .5, \
               "Avira": .5, "AVware": .5, "Baidu-International": .5, "BitDefender": .5, "Bkav": .5, \
               "ByteHero": .5, "CAT-QuickHeal": .5, "ClamAV": .5, "CMC": .5, "Comodo": .5, \
               "Cyren": .5, "DrWeb": .5, "Emsisoft": .5, "ESET-NOD32": .5, "Fortinet": .5, \
               "F-Prot": .5, "F-Secure": .5, "GData": .5, "Ikarus": .5, "Jiangmin": .5, \
               "K7AntiVirus": .5, "K7GW": .5, "Kaspersky": .5, "Kingsoft": .5, "Malwarebytes": .5, \
               "McAfee": .5, "McAfee-GW-Edition": .5, "Microsoft": .5, "MicroWorld-eScan": .5, \
               "NANO-Antivirus": .5, "nProtect": .5, "Panda": .5, "Qihoo-360": .5, "Rising": .5, \
               "Sophos": .5, "SUPERAntiSpyware": .5, "Symantec": .5, "Tencent": .5, "TheHacker": .5, \
               "TotalDefense": .5, "TrendMicro": .5, "TrendMicro-HouseCall": .5, "VBA32": .5, \
               "VIPRE": .5, "ViRobot": .5, "Zillya": .5, "Zoner": .5 \
              }
  weight = av_scores.get(input,.5)
  return weight

def main():
  opt=argparse.ArgumentParser(description="Search VirusTotal")
  opt.add_argument("HashorPath", help="Enter the MD5 Hash")
  opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
  opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDLXXX.json)")
  opt.add_argument("-c", "--classify", action="store_true",help="Attempts to classify the binary based on results")
  if len(sys.argv)<=2:
    opt.print_help()
    sys.exit(1)
  options= opt.parse_args()
  vt=vtAPI()
  md5 = checkMD5(options.HashorPath)
  if options.jsondump or options.verbose or options.classify:
    parse(vt.getReport(md5), md5 ,options.verbose, options.jsondump, options.classify)

if __name__ == '__main__':
    main()
