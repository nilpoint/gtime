#!/bin/bash

dir=`dirname $0`
tmp=${TMPDIR:-'/tmp/'}
# Test Anything Protocol, from http://testanything.org/
. ${dir}/tap-functions
host=${1:-'localhost'}

echo \# Using $host as Guardtime Gateway Server. Specify custom server as 1st command-line argument.

url_s="http://$host/gt-signingservice"
url_x="http://$host/gt-extendingservice"
url_p="http://verify.guardtime.com/gt-controlpublications.bin"

echo \# Running tests on `uname -n` at `date '+%F %T %Z'`

plan_tests 12 

diag "### Publications file download"
okx gtime-test -p -o ${tmp}/pub.bin -P $url_p

diag "### Verifying publications file"
okx gtime-test -v -b ${tmp}/pub.bin

diag "### Signing"
okx gtime-test -s -o ${tmp}/tmp.gtts -S $url_s

diag "### Verifying freshly created signature token"
okx gtime-test -v -i ${tmp}/tmp.gtts -b ${tmp}/pub.bin

like "`gtime-test -x -i ${tmp}/tmp.gtts -X $url_x 2>&1`" "try to extend later" "Extending freshly created signature token"

diag "### Verifying old timestamp"
okx gtime-test -v -b ${tmp}/pub.bin -i ${dir}/TestData.txt.gtts -f ${dir}/TestData.txt

diag "### Online verifying old timestamp"
okx gtime-test -vx -b ${tmp}/pub.bin -i ${dir}/TestData.txt.gtts -f ${dir}/TestData.txt -X $url_x

diag "### Extending timestamp"
okx gtime-test -x -i ${dir}/TestData.txt.gtts -o ${tmp}/ext.gtts -X $url_x

diag "### Verifying extended timestamp"
okx gtime-test -v -b ${tmp}/pub.bin -i ${tmp}/ext.gtts

diag "### Online verifying extended timestamp"
okx gtime-test -vx -b ${tmp}/pub.bin -i ${tmp}/ext.gtts -X $url_x

diag "### Using RIPEMD160"
okx gtime-test -s -F RIPEMD160:0a89292560ae692d3d2f09a3676037e69630d022 -o ${tmp}/r160.gtts -S $url_s
okx gtime-test -v -i ${tmp}/r160.gtts -f ${dir}/TestData.txt

# cleanup
rm -f ${tmp}/pub.bin ${tmp}/tmp.gtts ${tmp}/ext.gtts ${tmp}/r160.gtts 2> /dev/null
