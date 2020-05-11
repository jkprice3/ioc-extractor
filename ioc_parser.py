# IOC parser.py
# Written by Jason Price
# 5/7/2020 2:10 PM

import sys
import re

debug = 0

if len(sys.argv) < 2:
	print('Usage: ' + sys.argv[0] + ' <filename> [<debug bits 0-7>]')
	exit()
else:
	try:
		f = open(sys.argv[1],'r')
	except:
		print('Error opening file. File may not exist.')
		exit()
	if len(sys.argv) > 2:
		try:
			debug = int(sys.argv[2])
		except:
			debug = 0

# file to output to (CSV table)
output_path = 'parsed_iocs.csv'

# file to extract IOCs from
input_filename = sys.argv[1]

# file to get valid TLDs from
tlds_path = 'tlds.txt'
tlds_file = open(tlds_path,'r')
tlds = []
for line in tlds_file:
	tlds.append(line.strip().lower())

# patterns : dictionary with regex patterns for each IOC type
patterns = {'md5':r'(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])',
			'sha1':r'(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])',
			'sha256':r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])',
			'email_address':r'[a-zA-Z0-9_\-\.\+]+\[?@\]?([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]{2,24}',
			'ipv4':r'\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}',
			'ipv6':r'(?<![:.\w])(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}(?![:.\w])',
			'domain':r'(^|[^\.\-@/=a-zA-Z0-9])([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(XN--[a-zA-Z0-9\-]{2,24}|[a-zA-Z]{2,24})($|[^@/=])',
			'uri':r'[a-zA-Z]+://([a-zA-Z0-9\-]+\[?\.\]?)*[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]{2,24}(/\S+)?',
			'filename':r'(^|[^\.\-@/=a-zA-Z0-9])([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z\-]+[^@/=]',
			'ipv4port':r'\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}:\d{1,5}'}
			
matched_tokens = {}
regex_matches = {}
processed_matches = {}
for key in patterns: # Copy keys to other dict
	matched_tokens[key] = []
	regex_matches[key] = []
	processed_matches[key] = []
	
# PREPROCESSING
file = open(input_filename,'r')
for line in file: # Check each line
	for token in line.split(): # Check each token in the line
		ioc_match_type = ""
		for key in patterns: # Check each pattern against the token
			newtoken = re.sub(r'(\[|\])', '', token)
			m = re.search(patterns[key],newtoken)
			if m:
				matched_tokens[key].append(token)
				regex_matches[key].append(m.group(0))
		r = ioc_match_type
		
# PROCESSING
# Domain processing
for domain in regex_matches['domain']:
	m = re.search(r'(XN--[a-zA-Z0-9\-]{2,24}|[a-zA-Z]{2,24})$',domain)
	if m:
		possible_tld = m.group(0).lower()
		if possible_tld in tlds:
			processed_matches['domain'].append(domain)
			
# File name processing
for filename in regex_matches['filename']:
	# Exclude valid domain names because they are probably domain names
	m = re.search(r'(XN--[a-zA-Z0-9\-]{2,24}|[a-zA-Z]{2,24})$',filename)
	if m: # matches domain pattern
		possible_tld = m.group(0).lower()
		if not (possible_tld in tlds): # invalid TLD
			processed_matches['filename'].append(filename)
			continue
	else: # does not match domain pattern
		if not filename in matched_tokens['email_address']:
			print(filename)
			processed_matches['filename'].append(filename)
			continue

	

# IPv4 address processing
for ip in regex_matches['ipv4']:
	reject = False
	octets = ip.split('.')
	# a = int(octets[0])
	# if a in [0,10,127,223,239,240,255]:
		# reject = True
	# elif a in [100,169,172,192,198,203,223]:
		# useless_var = 0 
	for octet in octets:
		if int(octet) < 0 or int(octet) > 255:
			reject = True
	if not reject:
		processed_matches['ipv4'].append(ip)

# No Processing Required (direct copies, may be changed in the future)
for match in regex_matches['md5']:
	processed_matches['md5'].append(match)
for match in regex_matches['sha1']:
	processed_matches['sha1'].append(match)
for match in regex_matches['sha256']:
	processed_matches['sha256'].append(match)
for match in regex_matches['email_address']:
	processed_matches['email_address'].append(match)
for match in regex_matches['uri']:
	processed_matches['uri'].append(match)
for match in regex_matches['ipv6']:
	processed_matches['ipv6'].append(match)
for match in regex_matches['ipv4port']:
	processed_matches['ipv4port'].append(match)

# RESULTS
if debug % 2 == 1:
	print('\nPossible IOC matches - Preprocessed')
	for key in matched_tokens:
		print(key + ':')
		for match in matched_tokens[key]:
			print('\t' + match)

if debug % 4 >= 2:
	print('\nTight IOC matches - Preprocessed')
	for key in regex_matches:
		print(key + ':')
		for match in regex_matches[key]:
			print('\t' + match)
		
if debug % 8 >= 4:
	print('\nIOC matches - Processed')
	for key in processed_matches:
		print(key + ':')
		for match in processed_matches[key]:
			print('\t' + match)

outfile = open(output_path, 'w')
outfile.write('Indicator (Change Me),Type\n')
for key in processed_matches:
	for ioc in processed_matches[key]:
		outfile.write(ioc + ',' + key + '\n')