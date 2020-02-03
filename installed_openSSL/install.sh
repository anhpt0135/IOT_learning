#!/bin/bash

mount -o remount,rw "/usr/local/"
ret=$?

if [ ret -eq 0 ];then

	cp -R bin/* /usr/local/bin
	cp -R lib/* /usr/local/lib
	cp -R share/* /usr/local/share
	chmod 777 /usr/local/bin/openssl 
fi
