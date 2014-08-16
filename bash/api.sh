#!/bin/bash

function usage {
  echo "api.sh <cid> <secret> <path>"
  echo "with: cid - connect id"
  echo "      secret - api secret key"
  echo "      method - ie GET"
  echo "      path - api method to call, ie /profiles"
  exit 1
}

# input
CID=$1
SECRET=$2
METHOD=${3:-"GET"}
APICALL=${4:-"/profiles"}

if [ "$CID" = "" ];then
  usage
fi

if [ "$SECRET" = "" ];then
  usage
fi


# external programs used
OPENSSL="/usr/bin/openssl"
BASE64="/usr/bin/base64"
CURL="/usr/bin/curl"

# generate random nonce
NONCE=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 20 | head -n 1)

# now() timestamp in UTC format
NOW=$(LC_TIME="en_US.UTF-8" date -u +"%a, %d %b %Y %H:%M:%S GMT"  )

# api constants
PREFIX="ZXWS"
TYPE="json"
VERSION="2011-03-01"
HOST="api.zanox.com"

PATH="/$TYPE/$VERSION$APICALL" 

# authorization signature HMAC in base64
SIG="$METHOD$APICALL$NOW$NONCE"
MAC=$(echo -n $SIG | $OPENSSL dgst -binary -sha1 -hmac $SECRET | $BASE64 )

# authorization header with connect id
AUTH="$PREFIX $CID:$MAC"

# final URL to call
URL="http://$HOST/$PATH"

# here we go
DATA=$( $CURL -s -XGET -H"Host:$HOST" -H"Date:$NOW" -H"Nonce:$NONCE" -H"Authorization:$AUTH" "$URL")

# output result
echo $DATA

