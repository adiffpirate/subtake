# subtake

[![Build Status](https://travis-ci.org/jakejarvis/subtake.svg?branch=master)](https://travis-ci.org/jakejarvis/subtake)

Based on [@haccer](https://github.com/haccer)'s [subjack](https://github.com/haccer/subjack) script for subdomain takeover recon.

## Installation

Requires [Go](https://golang.org/dl/).

`go get github.com/jakejarvis/subtake`

## Usage

### Options

- `-f to-check.txt` is the path to your list of subdomains to check. One subdomain per line. **Required.**
- `-t` is the number of threads to use. (Default: 10)
- `-a` skips CNAME check and sends requests to every URL. (Default: false, but **Highly recommended.**) 
- `-timeout` is the number seconds to wait before timing out a check (Default: 10).
- `-o results.txt` is a filename to output results to. If the file ends with `.json`, subtake will automatically switch to JSON format.
- `-v` enables verbose mode. Displays all checks including not vulnerable URLs.
- `-c` Path to file containing JSON fingerprint configuration. (Default: `./fingerprints.json`)
- `-ssl` enforces HTTPS requests which may return a different set of results and increase accuracy.

### Resources

`sonar.sh` can be used first to gather a list of CNAMEs collected by Rapid7/scan.io's [Project Sonar](https://opendata.rapid7.com/sonar.fdns_v2/). This list can then be passed into subtake to return subdomains not in use. `sonar.sh` is based off of [`scanio.sh`](https://gist.github.com/haccer/3698ff6927fc00c8fe533fc977f850f8).

`fingerprints.json` can be modified to add or remove hosted platforms to probe for. Many obscure platforms are included, and removing fingerprints for services that are uninteresting to you can speed up the scan.

If you plan on using a high number of threads to speed the process up, you may need to [temporarily raise the `ulimit` of your shell](http://posidev.com/blog/2009/06/04/set-ulimit-parameters-on-ubuntu/):

```
ulimit -a          # show current limit (usually 1024)
ulimit -n 10000    # set waaaaay higher
ulimit -a          # check new limit
```

After generating a list of all vulnerable subdomains, you can use my [collection of domains invoked in bug bounty programs](https://github.com/jakejarvis/bounty-domains/blob/master/domains.txt) to narrow down valuable targets and possibly get some ca$h monie$$$.

### Examples

`./sonar.sh 2018-10-27-1540655191 sonar_all_cnames.txt`

`subtake -f sonar_all_cnames.txt -t 50 -ssl -a -o vulnerable.txt`

## Subdomain Takeover Tips

- A great explanation of the risks of takeovers and steps to responsibly disclose takeovers to companies: https://0xpatrik.com/subdomain-takeover/
- A comprehensive list of what services are vulnerable (and the basis of `fingerprints.json`), and how to proceed once finding them: https://github.com/EdOverflow/can-i-take-over-xyz

## Services Checked

- Acquia
- Airee.ru
- ~~Amazon CloudFront~~ [(no longer vulnerable?)](https://github.com/EdOverflow/can-i-take-over-xyz/issues/29)
- Apigee
- AWS/S3
- Big Cartel
- Bitbucket
- Brightcove
- Campaign Monitor
- Cargo Collective
- Fastly
- Feedpress
- Fly.io
- Ghost
- GitHub
- HatenaBlog
- Help Juice
- Help Scout
- Heroku
- MaxCDN
- Microsoft Azure
- Pantheon.io
- ReadMe.io
- Shopify
- Smugmug
- Statuspage
- Surge
- Tumblr
- UserVoice
- WordPress.com
- Zendesk


## To-Do

- Add a check for NS subdomains (https://0xpatrik.com/subdomain-takeover-ns/)
- Add Digital Ocean to the list 
