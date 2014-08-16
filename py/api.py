#!/usr/bin/python
import datetime
import random
import httplib
import hmac
import hashlib
import base64
import json
import pprint
import sys

class ZxApi(object):

    prefix = "ZXWS"
    datatype = "json"
    version = "2011-03-01"
    host = "api.zanox.com"
    
    def __init__(self,cid,secret):
        self.cid = cid
        self.secret = secret
        self.conn = httplib.HTTPConnection(ZxApi.host)


    def signature(self,verb,path,stamp,nonce):
        sig = verb + path + stamp + nonce
        mac = hmac.new(self.secret,sig,hashlib.sha1)
        dig = mac.digest()
        return base64.b64encode(dig)

    def getHeaders(self,method,path):

        nonce = (hashlib.sha1(str(random.random()))).hexdigest()[0:20]
        now = datetime.datetime.utcnow()
        stamp = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
    
        sig = self.signature(method, path ,stamp,nonce)
        auth = self.prefix + " " + self.cid + ":" + sig
        
        headers = {
            "Accept":"application/json",
            "Host"  : self.host,
            "Date"  : stamp,
            "Nonce" : nonce,
            "Authorization" : auth
        }
        return headers
        
    def send(self,method,path,params=""):

        self.conn.request(
            method, 
            "/" + ZxApi.datatype + "/" + ZxApi.version + path + params
            ,None,
            self.getHeaders(method,path)
        )

        res = self.conn.getresponse()
        data = res.read()

        result = json.loads(data)
        return result      
          
    
# handle cli args   
args = sys.argv[1:]
argc = len(args)
if argc < 3:
    print "usage: api.py <cid> <secret> <path>"
    print "with: cid - connect id"
    print "      secret - secret api key"
    print "      path - api method to call, ie /profiles"
    print "             with optional parameters"
    exit(0)
    
cid    = args[0]
secret = args[1]
path   = args[2]
params = ""

if argc > 3:
    params = "?" + args[3]
   
   
# initialize api object with cid and key
api = ZxApi(cid,secret)

# call api method and print result   
result = api.send("GET",path,params)

pprint.pprint(result)


