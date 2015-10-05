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
        self.api = 'XXXXXXXXXXXX' #insert your API here
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
    results = ""
    for x in it['scans']:
      if it['scans'][x]['detected'] == True:
        temp_result = it['scans'][x]['result']
        results = results + " " + str([temp_result.encode('UTF8')])
    extra = ['-','\[\'',':','.','\'\]','\/','!']
    rx = '[' + re.escape(''.join(extra)) + ']'
    final_ready = re.sub(rx,' ', results).replace('  ',' ')
    final = Counter(final_ready.split())
    print 'Guess: ', list(dict((k,v) for k,v in final.iteritems() if v > it['positives']/2).keys())
    print 'All results: ', final


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
  if options.search or options.jsondump or options.verbose or options.classify:
    parse(vt.getReport(md5), md5 ,options.verbose, options.jsondump, options.classify)

if __name__ == '__main__':
    main()
