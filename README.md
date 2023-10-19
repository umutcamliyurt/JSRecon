# JSRecon
## A powerful tool designed for identifying hidden endpoints and sensitive information within JavaScript files on a website.

<img src="background.png" width="900">

## Description:
JSRecon is a powerful tool designed for identifying hidden endpoints and sensitive information within JavaScript files on a website. It finds hidden URLs and hard-coded sensitive information to assist with detecting vulnerabilities.

<!-- FEATURES -->
## Features:

-  Fast crawler
- Finds sensitive information(API keys, e-mail(s), internal addresses...)
- Discovers hidden endpoints
- Built in Go

<!-- INSTALLATION -->
## Installation:

### Option 1:

[Download](https://github.com/Nemesis0U/JSRecon/releases) from releases

### Option 2:
Run the following command to get the repo:

    $ go install -v github.com/Nemesis0U/JSRecon@latest

<!-- USAGE -->
## Usage:

### Options:

```
./jsrecon -h
NAME:
   JSRecon - Scan and extract endpoint URLs and sensitive data from JS files on a website

USAGE:
   JSRecon [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --url value, -u value     URL of the website to scan (required)
   --keyword value           Keyword to search for in JavaScript code (optional)
   --output value, -o value  Output file to save the links (optional)
   --show-as-domain          Show results as domains instead of full URLs (optional) (default: false)
   --show-sensitive          Show sensitive data found in JS files (optional) (default: false)
   --cookie value            Custom cookie to include in the request (optional)
   --help, -h                show help

```
<!-- EXAMPLE -->
### Example:

```
./jsrecon -u https://www.tiktok.com --show-sensitive --output results.txt --show-as-domain

Data saved to results.txt

IP Address: 1.0.0.73
IP Address: 1.0.1.234
API Key: 3319de946467a5e2530ff6f04830521452419c9a548f85fca089ebc9cf8c22a8
Credential: username
Credential: Username
Credential: Password
Credential: password
Email Address: roaogardo@gmail.com
Email Address: nemilio@tripon-entertainment.com
Email Address: smashingpencilsart@gmail.com
Email Address: Raziirawani@gmail.com
Email Address: nbellarteskids@gmail.com
API Key: 2023101515264400AB6AE6E1431E45CF25
API Key: 858a8ca65482457eac325ed2eeb463b0
API Key: f0dae91b3b5c2419f57f9e25a02df551
API Key: 47ee01b829cee66c47ef333f6fd4d7bb
API Key: f549fe8da2aebb5b2bae6f5389b6a016

...

IP Address: 1.0.0.201
Credential: secret
sf16-website-login.neutral.ttwstatic.com
lf16-tiktok-web.tiktokcdn-us.com
im-api-va.tiktok.com
m.tiktok.com
www.tiktok.com
starling-oversea.byteoversea.com
mcs-va-useast2a.tiktokv.com
vmweb-va.byteoversea.com
webcast.tiktok.com
f-p.sgsnssdk.com
sf16-tcc-tos-va.byteoversea.com
api.tiktok.com
```
<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.
