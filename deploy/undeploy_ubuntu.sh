#!/bin/bash
#undeploy OpenAttestation 2.x

mysql_password={mysql_password:-""}

example()
{
    echo $"$0: Usage: $0 --mysql <MySQL passwd of oat server>"
}

[ "$1" != "--mysql" ] && example && exit 1

if [ $# -lt 2 ];then
    mysql -uroot -e 'drop database mw_as';
else
    mysql_password=$2
    mysql -uroot -p$mysql_password -e 'drop database mw_as';
fi

conf_dir=${conf_dir:-/etc/intel/cloudsecurity}
tomcat_dir=${tomcat_dir:-/var/lib/tomcat7}
oat_home_dir=${oat_home_dir:-$HOME/.oat}

delete()
{
  rm -rf $1
}

delete "$conf_dir/*"
delete "$oat_home_dir/*"

line="`grep -n "<\/Service>" $tomcat_dir/conf/server.xml | \
       awk -F: '{print $1}'`"
line=$[$line - 1]
str="`sed -n "$line p" $tomcat_dir/conf/server.xml | grep "Connector"`"
[[ ! -z $str ]] && \
    sed -i "$line d" $tomcat_dir/conf/server.xml

delete "$tomcat_dir/webapps/HisPrivacyCAWebServices2*"
delete "$tomcat_dir/webapps/WLMService*"
delete "$tomcat_dir/webapps/WhiteListPortal*"
delete "$tomcat_dir/webapps/AttestationService*"
delete "$tomcat_dir/webapps/TrustDashBoard*"
