#!/bin/bash
#deploy OpenAttestation 2.x

### configuration ###
mysql_password=${mysql_password:-""}
oat_server=${oat_server:-""}
oat_server_port=${oat_server_port:-8181}
mysql_port=${mysql_port:-3306}
saml_password=${saml_password:-samlpasswd2}
portal_password=${portal_password:-portalpasswd2}
p12_password=${p12_password:-p2}
log_dir=${log_dir:-/var/log/tomcat}

example()
{
    echo $"$0: Usage: $0 --mysql <MySQL passwd of oat server> --ip <IP of oatserver> --port <Port of oatserver> --mysql_port <Port of mysql> --ha_master <IP of the ha master>"
}

if [ $# -lt 3 ]; then
    example
    exit 1
fi

while [ $# -gt 1 ]; do
  case $1 in
    --mysql)
        if [ "$2" != "--ip" ];then
            mysql_password=$2
            shift 2
        else
            shift 1
        fi
        ;;
    --ip)
        oat_server=$2
        shift 2
        ;;
    --port)
        oat_server_port=$2
        shift 2
        ;;
    --mysql_port)
        mysql_port=$2
        shift 2
        ;;
    --ha_master)
        ha_master=$2
        shift 2
        ;;
    *)
        example
        exit 1;;
  esac
done

echo "oat_server = $oat_server"
echo "mysql_password = $mysql_password"
echo "oat_server_port = $oat_server_port"

if [ "$oat_server" == "" ]; then
    example
    exit 1
fi

###########
TOP_DIR=$(cd .. && pwd)
conf_dir=${conf_dir:-/etc/intel/cloudsecurity}
[ -d $conf_dir ] && rm -rf $csonf_dir
install -d  $conf_dir
chown -R tomcat:tomcat $conf_dir

tomcat_dir=${tomcat_dir:-/usr/share/tomcat}
oat_home_dir=${oat_home_dir:-$HOME/.oat}
[ -d $oat_home_dir ] && rm -rf $oat_home_dir
install -d  $oat_home_dir
chown -R tomcat:tomcat $oat_home_dir

###MySQL ###
mysql_status="`netstat -vulntp |grep -i mysqld`"
if [ -n "$mysql_status" ];then
    echo "mariaDB service is running .."
else
    echo "starting mariaDB service .."
    service mariadb start
fi
if [ "$mysql_password" == "" ];then
    mysql -uroot -e 'create database mw_as';
    mysql -uroot mw_as < \
    $TOP_DIR/database/mysql/src/main/resources/com/intel/mtwilson/database/mysql/mtwilson.sql
else
    mysql -uroot -p$mysql_password -e 'create database mw_as';
    mysql -uroot -p$mysql_password mw_as < \
    $TOP_DIR/database/mysql/src/main/resources/com/intel/mtwilson/database/mysql/mtwilson.sql
fi

# grant root all the permissions
mysql -uroot -p$mysql_password mysql -e "grant all privileges on *.* to root@'%' identified by '$mysql_password'"

cd $conf_dir
mtwilson_properties()
{
    cat <<EOF > $conf_dir/mtwilson.properties
mtwilson.api.baseurl=https://OATAPPR_IP:$oat_server_port
mtwilson.api.ssl.policy=TRUST_FIRST_CERTIFICATE
mtwilson.db.driver=com.mysql.jdbc.Driver
mtwilson.db.url=jdbc:mysql://OATAPPR_IP:$mysql_port/mw_as
mtwilson.db.user=root
mtwilson.db.password=MYSQL_PASSWD
EOF
}

trust_properties()
{
    cat <<EOF > $conf_dir/trust-dashboard.properties
mtwilson.tdbpkeystore.dir=/etc/intel/cloudsecurity
mtwilson.tdbp.keystore.password=PORTAL_PASSWD
imagesRootPath= images/
trustUnknow = images/Unknown.png
trustTure = images/Trusted.png
trustFalse = images/UnTrusted.png
ubuntu = images/ubuntu.png
vmware = images/vmware.png
suse = images/suse.png
kvm = images/kvm.png
xen = images/xen.png
mtwilson.tdbp.sessionTimeOut = 1800
mtwilson.tdbp.paginationRowCount = 10
EOF
}


whitelist_properties()
{
    cat <<EOF > $conf_dir/whitelist-portal.properties
mtwilson.wlmp.keystore.dir=/etc/intel/cloudsecurity
mtwilson.wlmp.keystore.password=PORTAL_PASSWD
mtwilson.wlmp.openSourceHypervisors=KVM;Xen
mtwilson.wlmp.sessionTimeOut=1800
mtwilson.wlmp.pagingSize=8
EOF
}


attestation_properties()
{
    cat <<EOF > $conf_dir/attestation-service.properties
com.intel.mountwilson.as.trustagent.timeout=3
com.intel.mountwilson.as.attestation.hostTimeout=60
com.intel.mountwilson.as.home=/var/opt/intel/aikverifyhome
com.intel.mountwilson.as.aikqverify.cmd=aikqverify
com.intel.mountwilson.as.openssl.cmd=openssl.sh
saml.key.alias=samlkey1
saml.keystore.file=SAML.jks
saml.keystore.password=SAML_KEYSTORE_PASSWD
saml.validity.seconds=3600
saml.issuer=https://OATAPPR_IP:$oat_server_port
saml.key.password=SAML_KEY_PASSWD
privacyca.server=OATAPPR_IP
com.intel.mtwilson.as.buisiness.trust.sleepTime=1
EOF
}

privacyca_client_properties()
{
    cat <<EOF > $conf_dir/privacyca-client.properties
PrivacyCaUrl=https://OATAPPR_IP:$oat_server_port/HisPrivacyCAWebServices2
PrivacyCaSubjectName=HIS_PRIVACY_CA
PrivacyCaPassword=***replace***
EndorsementCaSubjectName=Endorsement_CA_Rev_1
EndorsementCaPassword=***replace***
CertValidityDays=3652
AikAuth=1111111111111111111111111111111111111111
ecStorage=NVRAM
ecSigningKeySize=2048
ecLocation=/opt/intel/cloudsecurity/trustagent
TpmOwnerAuth=1111111111111111111111111111111111111111
EOF
}


privacyca_properties()
{
   cat <<EOF > $conf_dir/PrivacyCA.properties
ClientFilesDownloadUsername=admin
ClientFilesDownloadPassword=PRIVACY_CA_PASSWD
EOF
}

install_aikverify()
{
    ### aikqverify install ###
    pdir=$(pwd)
    [ -e $oat_home_dir/aikqverify-* ] &&  \
        rm -rf $oat_home_dir/aikqverify-*

    find $TOP_DIR -name "aikqverify-*.zip"  | \
        xargs -i unzip {} -d $oat_home_dir
    cd $oat_home_dir/aikqverify-*
    make
    make install
    cd $pdir
}

### copy oat war packages ###
copy_war_package()
{
    find $TOP_DIR -name "$1*.war" | \
        xargs -i cp {} $tomcat_dir/webapps/$1.war
}

is_hamaster()
{
    for host in `hostname -I`;
    do
        if [[ $1 == $host ]]; then
            return 0
            break;
        fi
    done
    if [[ $1 =~ `hostname` ]]; then
    return 0
    fi
    return 1
}

if [ -n "$ha_master" ]; then
    if ! is_hamaster $ha_master; then
        # ha slave node
        # copy the certificates and property file to slave
        echo "ha slave"
        for pth in $conf_dir $tomcat_dir/Certificate $oat_home_dir $tomcat_dir/conf/server.xml;
        do
            echo "Transfering $ha_master:$pth to $pth..."
            rsync -avz $ha_master:$pth `dirname $pth`
        done

        # install aikverify
        install_aikverify

        # grant root all the permission
        #mysql -uroot -p$mysql_password mysql -e "grant all privileges on *.* to root@'%' identified by '$mysql_password'"

        # copy wars
        for name in "HisPrivacyCAWebServices2" "WLMService" \
            "WhiteListPortal" "AttestationService" "TrustDashBoard";
        do
            echo "Copying $name.war to tomcat webapp."
            copy_war_package $name
        done

        # set permissions
        chown -R tomcat:tomcat $conf_dir
        chown -R tomcat:tomcat $tomcat_dir/Certificate
        chown -R tomcat:tomcat /var/opt

        service tomcat restart
        exit 0
        fi
fi

mtwilson_properties
trust_properties
whitelist_properties
attestation_properties
privacyca_properties
privacyca_client_properties

sed -i "s/OATAPPR_IP/$oat_server/g" $conf_dir/mtwilson.properties
sed -i "s/OATAPPR_IP/$oat_server/g" $conf_dir/attestation-service.properties
sed -i "s/OATAPPR_IP/$oat_server/g" $conf_dir/privacyca-client.properties
sed -i "s/MYSQL_PASSWD/$mysql_password/g" $conf_dir/mtwilson.properties
sed -i "s/PORTAL_PASSWD/$portal_password/g" $conf_dir/trust-dashboard.properties
sed -i "s/PORTAL_PASSWD/$portal_password/g" $conf_dir/whitelist-portal.properties
sed -i "s/SAML_KEYSTORE_PASSWD/$saml_password/g" $conf_dir/attestation-service.properties
sed -i "s/SAML_KEY_PASSWD/$saml_password/g" $conf_dir/attestation-service.properties
sed -i "s/PRIVACY_CA_PASSWD/$p12_password/g" $conf_dir/PrivacyCA.properties

att_parse()
{
  cat $conf_dir/attestation-service.properties | \
      grep "$1" | awk -F= '{print $2}'
}

trust_tdb_parse()
{
  cat $conf_dir/trust-dashboard.properties | \
      grep "$1" | awk -F= '{print $2}'
}

saml_key_alias="`att_parse "saml.key.alias"`"
saml_keystore_file="`att_parse "saml.keystore.file"`"
saml_keystore_password="`att_parse "saml.keystore.password"`"
saml_key_password="`att_parse "saml.key.password"`"
server_keystore_password="`date  +%s%N`"
server_key_password=$server_keystore_password

### Create SAML Signing Key ###
keytool -genkey -alias $saml_key_alias -keyalg RSA -keysize 2048 \
        -keystore $saml_keystore_file -storepass $saml_keystore_password \
        -dname "CN=AttestationService, OU=MtWilson, O=MyOrg, C=US" \
        -validity 3650 -keypass $saml_key_password

keytool -export -alias $saml_key_alias -keystore $saml_keystore_file \
        -storepass $saml_keystore_password -file $oat_home_dir/saml.crt

### Create EK Signing Certificate ###
pushd $(pwd)
cd $log_dir
find $TOP_DIR -name "HisPrivacyCAWebServices2*-setup.jar" | \
      xargs -i java -jar {} 
popd
cp $conf_dir/clientfiles/PrivacyCA.cer $conf_dir

### aikqverify install ###
install_aikverify
#pdir=$(pwd)
#[ -d $oat_home_dir/aikqverify-* ] &&  \
#    rm -rf $oat_home_dir/aikqverify-*

#find $TOP_DIR -name "aikqverify-*.zip"  | \
#    xargs -i unzip {} -d $oat_home_dir
#cd $oat_home_dir/aikqverify-*
#make
#make install
#cd $pdir

### Create Attestation Server Certificate ###
privacyca_server="`att_parse "privacyca.server"`"
install -d $tomcat_dir/Certificate
chown -R tomcat:tomcat $tomcat_dir/Certificate/
chown -R tomcat:tomcat /var/opt

[ -e $tomcat_dir/Certificate/keystore.jks ] && \
     rm -f $tomcat_dir/Certificate/keystore.jks

[ -e $tomcat_dir/Certificate/ssl.${privacyca_server}.crt ] && \
     rm -f $tomcat_dir/Certificate/ssl.${privacyca_server}.crt

keytool -genkey -alias s1as -keyalg RSA -keysize 2048 \
        -keystore $oat_home_dir/keystore.jks -storepass $server_keystore_password \
        -dname "CN=${privacyca_server}, OU=Mt Wilson, O=My Org, C=US" \
        -validity 3650 -ext san=IP:${privacyca_server} \
        -keypass $server_key_password

keytool -exportcert -alias s1as -keystore $oat_home_dir/keystore.jks \
        -storepass $server_keystore_password \
        -file $oat_home_dir/ssl.${privacyca_server}.crt

cp -f $oat_home_dir/keystore.jks $tomcat_dir/Certificate/
cp -f $oat_home_dir/ssl.${privacyca_server}.crt $tomcat_dir/Certificate/

### Create Portal Signing Key ###
tdbp_password="`trust_tdb_parse "mtwilson.tdbp.keystore.password"`"

keytool -genkey -alias admin -keyalg RSA -keysize 2048 -keystore $oat_home_dir/portal.jks \
        -storepass $tdbp_password -dname "CN=Portal User, OU=Mt Wilson, O=My Org, C=US" \
        -validity 3650 -keypass $tdbp_password

keytool -importcert -file $oat_home_dir/saml.crt -keystore $oat_home_dir/portal.jks \
        -storepass $tdbp_password -alias "mtwilson (saml)"

keytool -importcert -file $oat_home_dir/ssl.${privacyca_server}.crt  \
        -keystore $oat_home_dir/portal.jks \
        -storepass $tdbp_password -alias "mtwilson (ssl)"

sed -i "/<\/Service>/i\    <Connector port=\"8181\" minSpareThreads=\"5\" maxSpareThreads=\"75\" enableLookups=\"false\" disableUploadTimeout=\"true\" acceptCount=\"100\" maxThreads=\"200\" scheme=\"https\" secure=\"true\" SSLEnabled=\"true\" clientAuth=\"want\" sslProtocol=\"TLS\" ciphers=\"TLS_ECDH_anon_WITH_AES_256_CBC_SHA, TLS_ECDH_anon_WITH_AES_128_CBC_SHA, TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_DSS_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA\" keystoreFile=\"Certificate\/keystore.jks\" keystorePass=\"$server_keystore_password\" truststoreFile=\"Certificate\/keystore.jks\" truststorePass=\"$server_key_password\"\/>" $tomcat_dir/conf/server.xml

### copy oat war packages ###
#copy_war_package()
#{
#    find $TOP_DIR -name "$1*.war" | \
#        xargs -i cp {} $tomcat_dir/webapps/$1.war
#}

copy_war_package "HisPrivacyCAWebServices2"
copy_war_package "WLMService"
copy_war_package "WhiteListPortal"
copy_war_package "AttestationService"
copy_war_package "TrustDashBoard"

#Create cacert and key
export javaCmd="'$TOP_DIR/services/AttestationService/target/AttestationService-2.3/WEB-INF/lib/AttestationService-2.3.jar:$TOP_DIR/services/AttestationService/target/AttestationService-2.3/WEB-INF/lib/*' com.intel.mtwilson.tag.setup.cmd.TagCreateCaKey 'CN=asset-tag-service,OU=oat'"
echo "#!/bin/bash
java -cp $javaCmd" > javaCmdScript.sh
chmod +x javaCmdScript.sh
./javaCmdScript.sh
rm javaCmdScript.sh


### tomcat restart ###
service tomcat restart

