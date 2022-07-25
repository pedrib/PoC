# Multiple vulnerabilities in TIBCO Data Virtualization (versions 8.3 and below) 
### By Pedro Ribeiro (pedrib@gmail.com | [@pedrib1337](https://twitter.com/pedrib1337)) from [Agile Information Security](https://agileinfosec.co.uk)

#### Disclosure: 2021-07-16 / Last updated: 2021-07-16

* [Summary](#summary)
* [Vulnerability Details](#vulnerability-details)
    * [#1: Unsafe Flex AMF Java Object Deserialization](#1-unsafe-flex-amf-java-object-deserialization)
    * [#2: Use of Insecure Java Library](#2-use-of-insecure-java-library)
* [Exploit Chain](#exploit-chain)
* [Disclosure Process](#disclosure-process)
* [Fixes / Mitigations](#fixes--mitigations)

## Product Information
[From the vendor's website](https://docs.tibco.com/products/tibco-data-virtualization-8-4-0):
> TIBCO® Data Virtualization integrates disparate data sources in real-time instead of copying their data into a data warehouse. TIBCO® Data Virtualization (TDV) allows you to easily create logical views to integrate and secure data across disparate data sources and tailor it to your analytical needs. TDV connects to virtually any data source and provides business users access to data through JDBC, ODBC, ADO.NET, REST and SOAP.


## Summary
[TIBCO](https://www.tibco.com) Data Virtualization (TDV) is a product for data processing and analytics which can be installed onto Linux and Windows hosts. Interaction with the software is done over a Web interface on port 9400.

TDV exposes an unauthenticated Action Message Format (AMF) API endpoint that is vulnerable to insecure Java deserialization. By abusing this deserialization and combining it with an outdated Java library that contains a gadget chain, it is possible to achieve remote code execution as root on Linux or SYSTEM on Windows.

This vulnerability chain affects all versions of TDV up to 8.3 and below, and it is exploitable on Linux and Windows hosts. A [Ruby exploit](https://github.com/pedrib/PoC/blob/master/exploits/tdvPwn.rb) which abuses this vulnerability chain was released with [this advisory](https://github.com/pedrib/PoC/blob/master/advisories/TIBCO/tibco_tdv_rce.md).

I attempted to disclose these vulnerabilities responsibly to TIBCO, but they refused to acknowledge my vulnerability report. More details are in the [Disclosure Process](#disclosure-process) section.

A video of the exploit in action [can be seen here](https://github.com/pedrib/PoC/blob/master/advisories/TIBCO/tibco_tdv_rce.mkv).


## Vulnerability Details
### #1: Unsafe Flex AMF Java Object Deserialization
* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [CVE-2017-5641](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5641)
* Risk Classification: Critical
* Attack Vector: Remote
* Constraints: None
* Affected versions: TIBCO Data Virtualization 8.3 and below

By sending an HTTP POST request with random data to */monitor/messagebroker/amf*, the server will respond with a 200 OK and binary data that includes:
```
 ...Unsupported AMF version XXXXX...
```

Which indicates that the server has a Apache / Adobe Flex AMF (BlazeDS) endpoint at that location. The BlazeDS library version running on the server is 3.2.0.3978, which means it is [vulnerable to CVE-2017-5641](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5641), the description of which is copied below:

> "Previous versions of Apache Flex BlazeDS (4.7.2 and earlier) did not restrict which types were allowed for AMF(X) object deserialization by default. During the deserialization process code is executed that for several known types has undesired side-effects. Other, unknown types may also exhibit such behaviors. One vector in the Java standard library exists that allows an attacker to trigger possibly further exploitable Java deserialization of untrusted data. Other known vectors in third party libraries can be used to trigger remote code execution."

I previously exploited this vulnerability in [DrayTek VigorACS](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/draytek-vigor-acs.txt) and [Cisco ISE](https://github.com/pedrib/PoC/blob/master/exploits/ISEpwn/ISEpwn.rb).

Given the complexity of AMF and the Java deserialization chain involved, it is out of scope of this advisory to go into details. The only takeaway necessary is that under the right conditions, as it will be explained in [Exploit Chain](#exploit-chain), it is possible to achieve remote code execution. 

Readers interested in digging deeper should check out the write-up [AMF - Another Malicious Format](http://codewhitesec.blogspot.ru/2017/04/amf.html) by Markus Wulftange as well as [Java Unmarshaller Security - Turning your data into code execution](https://github.com/mbechler/marshalsec) by Moritz Bechler for further details on this vulnerability.


### #2: Use of Insecure Java Library
* [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
* [CVE-2016-2510](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2510)
* Risk Classification: High
* Attack Vector: N/A
* Constraints: N/A
* Affected versions: all current TIBCO Data Virtualization versions including the latest 8.4

TDV ships with a very old version of the Java BeanShell library, version 2.0b4, [which is at least 7 years old](https://github.com/beanshell/beanshell/releases/tag/2.0b5) at the time of writing. 
This version contains a Java deserialization gadget chain that can be abused to execute code under the right conditions. 
There is a payload for this library in the famous [*ysoserial*](https://github.com/frohoff/ysoserial) Java deserialization exploitation tool, which is named [*BeanShell1*](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/BeanShell1.java). 


## Exploit Chain
The exploit chain seems simple at first glance. As I have previously shown in my [DrayTek VigorACS](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/draytek-vigor-acs.txt) and [Cisco ISE](https://github.com/pedrib/PoC/blob/master/exploits/ISEpwn/ISEpwn.rb) exploits, the "normal" exploitation process abuses the *ysoserial* [JRMP payload](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPListener.java) to return a malicious object to the caller. 
This technique works on TDV versions 8.2 and below, but not on 8.3. This is due to 8.3 using a newer Java version that has [JEP-290](https://openjdk.java.net/jeps/290) to filter certain known bad classes and protect against malicious [remote method invocations](https://dzone.com/articles/a-first-look-into-javas-new-serialization-filterin) (RMI).

While there are multiple [write-ups](
https://mogwailabs.de/en/blog/2020/02/an-trinhs-rmi-registry-bypass/) on [bypasses](https://nsfocusglobal.com/java-deserialization-exploits-registry-whitelist-bypass/), none of them worked, so it was impossible to use the JRMP technique for version 8.3.

However, [Matthias Kaiser](https://twitter.com/matthias_kaiser) was able to find two other ways to achieve remote code execution with AMF endpoints that work without RMI, therefore bypassing JEP-290 entirely. They are detailed in an excellent blog post [Exploiting Adobe ColdFusion before CVE-2017-3066](https://codewhitesec.blogspot.com/2018/03/exploiting-adobe-coldfusion.html).

Thankfully, his Externalizable based *org.apache.axis2.util.MetaDataEntry* technique works just fine in TDV 8.3 and below, creating a universal exploit for all affected versions!

The [exploit released with this advisory](https://github.com/pedrib/PoC/blob/master/exploits/tdvPwn.rb) performs the following actions:

1. Uses *ysoserial* to generate a *BeanShell1* payload with the command to be executed.
2. Replaces the *serialVersionUID* of the *BeanShell* classes used by *ysoserial* (2.0b5) with the ones used by TDV (2.0b4)
3. Wraps everything in a *org.apache.axis2.util.MetaDataEntry*
4. Then wraps everything again in an AMF Message object and sends it off to the remote server

... which results in remote code execution as root on Linux and SYSTEM on Windows!
Please refer to the [video released with this advisory](https://github.com/pedrib/PoC/blob/master/advisories/TIBCO/tibco_tdv_rce.mkv) to see it in action.


## Disclosure Process:
The disclosure process was a complete disaster. I first contacted TIBCO on 2021-07-05, informing them of the vulnerability chain and asking them to confirm my suspicion that 8.4 was not vulnerable, and whether they were going to release an advisory telling their customers to upgrade to 8.4 (since 8.3 was still being offered for download).

The reply came one day later and it read:
> Thank you for your report. We are actively investigating the details you have provided and we will be back with you shortly. TIBCO has a “Fair Disclosure” policy which does not allow us to confirm issues before they are fixed, which may contribute to response time. For complete details on our disclosure policies, please refer to https://www.tibco.com/security/vulnerability-disclosure-policy
  
Mind boggling. They refuse to acknowledge vulnerabilities to the researcher who reported them? Does this make any sense? And they have the gall of calling it "Fair Disclosure"!

A look at their [vulnerability disclosure policy](https://www.tibco.com/security/vulnerability-disclosure-policy) shows:

> TIBCO takes security very seriously. TIBCO’s policies are designed to treat the users of our software equally with respect to vulnerability disclosure and remediation.

If their policy starts with *"we take security very seriously"*, then it's going to be downhill from here and it is clear what they really mean (hint: they **DON'T** take security seriously). 

Still, it doesn't say anywhere that they don't confirm security issues to whoever reported them? I responded with a polite email saying that I can wait for confirmation, but please come back to me on whether you will issue an advisory, inform your customers and if they can mention my name as the vulnerability discoverer. Their response was:

> Unfortunately, I am unable to answer any of your questions due to TIBCO’s security policy https://www.tibco.com/security/vulnerability-disclosure-policy
> I will update you as soon as I can. 

Unbelievable. Another look at their [vulnerability disclosure policy](https://www.tibco.com/security/vulnerability-disclosure-policy) shows:

> Coordinated Disclosure - TIBCO encourages security researchers to report to us any vulnerabilities that they find in our offerings. Our principle of coordinated disclosure requires that we work together in a constructive manner with security researchers who report vulnerabilities to ensure that the vulnerability is fully remediated and subsequent disclosure is coordinated.

Does this sound like "fair" or coordinated disclosure? In what planet? I then sent a much more angry email, asking again for confirmation whether they will credit me, issue an advisory for their customers, etc. Their answer was again a non answer:

> Pedro, to answer your question, If a security vulnerability were determined to exist in TIBCO code, then as a CNA we would assign a CVE and announce the vulnerability along with a remediation. If an undisclosed security vulnerability was determined to exist in third party code, we would work with that third party to achieve a resolution. TIBCO does not assign CVEs nor issue security advisories for third party code.

So they don't acknowledge my report, they don't confirm if their product is vulnerable (obviously it is, I had a fully working remote exploit at this point), and refuse to say whether they will credit me or even issue an advisory. 

My final email was a very angry rant telling them what I think of their disclosure policy and that I am going to release this advisory and exploit without their consent.

I will refrain from commenting further, as it is clear to anyone who reads this that their vulnerability disclosure process is not fit for purpose. I hope they change it after this debacle, although I am not holding my breath.

## Fixes / Mitigations:
Upgrade TIBCO Data Virtualization to the latest 8.4 version, released on 2021-05-04, which removes the AMF endpoint, rendering this vulnerability chain unexploitable.


## Disclaimer
Please note that Agile Information Security Limited (Agile InfoSec) relies on information provided by the vendor / product manufacturer when listing fixed versions, products or releases. Agile InfoSec does not verify this information, except when specifically mentioned in the advisory text and requested or contracted by the vendor to do so.
Unconfirmed vendor fixes might be ineffective, incomplete or easy to bypass and it is the vendor's responsibility to ensure all the vulnerabilities found by Agile InfoSec are resolved properly. Agile InfoSec usually provides the information in its advisories free of charge to the vendor, as well as a minimum of six months for the vendor to resolve the vulnerabilities identified in its advisories before they are made public.
Agile InfoSec does not accept any responsibility, financial or otherwise, from any material losses, loss of life or reputational loss as a result of misuse of the information or code contained or mentioned in its advisories. It is the vendor's responsibility to ensure their products' security before, during and after release to market.

## License
All information, code and binary data in this advisory is released to the public under the [GNU General Public License, version 3 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.en.html). For information, code or binary data obtained from other sources that has a license which is incompatible with GPLv3, the original license prevails.
