#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import time
pathdir = '/var/www/html/'
#pathdir = '/var/www/html/phpmyadmin'		
wafpath = '/var/www/html/my_waf/waf.php'
#wafpath = '/var/www/html/waf/waf.php'
#wafpath = '/var/www/html/waf/capture.php'
#wafpath = '/var/www/html/waf/ip_forbidden.php'	
wis = 'php|pht'
filepaths = []		
for fpathe,dirs,fs in os.walk(pathdir):
	for f in fs:
		ppp = os.path.join(fpathe,f)
		if os.path.isfile(ppp) and re.match(r'^\.('+wis+')$',os.path.splitext(ppp)[1]):
			filepaths.append(ppp)
for f in filepaths:
	if f!=wafpath:
		print f
		insert_line = '@include_once("'+wafpath+'");\n';
	lines = open(f).readlines()
	res = ''
	php_flag = False	#avoid the html page content
	is_insert = False
	for line in lines:
		if line.startswith('<?php'):
			php_flag = True
			res += line 
			continue
		if line.replace("\n","").replace(" ","").replace("\r","")=="":
			continue
		if not line.startswith('use') and not line.startswith('namespace') and not line.startswith('/') and not line.startswith(' *') and php_flag and not is_insert:
			res += insert_line
			is_insert = True
		res += line
	open(f,'w').write(res)
	if not is_insert:
		print "warning: %s not modified" %f
	
	

