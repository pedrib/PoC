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
