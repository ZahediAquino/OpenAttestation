/*
 * Copyright (c) 2013, Intel Corporation. 
 * All rights reserved.
 * 
 * The contents of this file are released under the BSD license, you may not use this file except in compliance with the License.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of Intel Corporation nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.intel.mountwilson.as.common;

import com.intel.mtwilson.io.ConfigurationUtil;
import java.net.MalformedURLException;
import java.net.URL;
import java.io.File;
import java.util.prefs.Preferences;
import com.intel.mtwilson.util.ConfigBase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import org.apache.commons.configuration.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Attempts to use commons-configuration to load the Attestation Service settings.
 * 
 * The configuration is loaded in the following priority order:
 * System properties
 * Properties in the file attestation-service.properties (create this file in your classpath or home directory to customize local settings)
 * Properties in the file attestation-service-defaults.properties (included with ASCommon)
 * Hard-coded defaults (defined in this class)
 * 
 * The attestation-service.properties file can be placed in your home directory 
 * in order to customize the application settings for your machine.
 * 
 * XXX CHANGE:  no longer using the attestation-service-config.xml file or the attestation-service-defaults.properties file in the classpath
 * 
 * @author jabuhacx
 */
public class ASConfig extends ConfigBase{
    
    private static final ASConfig global = new ASConfig();
    public static Configuration getConfiguration() { return global.getConfigurationInstance(); }
           
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    @Override
    public Properties getDefaults() {
        Properties defaults = new Properties();
        defaults.setProperty("com.intel.mountwilson.as.home", "C:/work/aikverifyhome"); // used by TAHelper
        defaults.setProperty("com.intel.mountwilson.as.openssl.cmd", "openssl.bat"); // used by TAHelper
        //defaults.setProperty("com.intel.mountwilson.as.aikqverify.cmd", "aikqverify.exe"); // used by TAHelper
        defaults.setProperty("com.intel.mountwilson.as.trustagent.timeout", "3"); // seconds
        defaults.setProperty("com.intel.mountwilson.as.attestation.hostTimeout","30");  // seconds
        // mtwilson.as.dek = base64-encoded AES key used by HostBO
        // mtwilson.taca.keystore.password
        // mtwilson.taca.key.alias
        // mtwilson.taca.key.password
        return defaults;
	}

    
    private ASConfig() {
        
        super("attestation-service.properties");
    }
    
 
    public static Properties getASDataJpaProperties() {
        Configuration myConfig = getConfiguration();
        Properties prop = new Properties();
        prop.put("javax.persistence.jdbc.driver", myConfig.getString("mountwilson.as.db.driver", getDatabaseDriver()));
        Object toCompare = prop.get("javax.persistence.jdbc.driver");
        if(prop.size() > 0 && (null != toCompare && toCompare.equals("com.mysql.jdbc.Driver"))) {
            prop.put("javax.persistence.jdbc.scheme", "mysql"); // NOTE: this is NOT a standard javax.persistence property, we are setting it for our own use
        }
//        else if( prop.get("javax.persistence.jdbc.driver").equals("org.postgresql.Driver") ) {
//            prop.put("javax.persistence.jdbc.scheme", "postgresql"); // NOTE: this is NOT a standard javax.persistence property, we are setting it for our own use
//        }
        else {
            prop.put("javax.persistence.jdbc.scheme", "unknown-scheme");
        }
        
        prop.put("javax.persistence.jdbc.host", myConfig.getString("mountwilson.as.db.host", getDatabaseHost()));
        prop.put("javax.persistence.jdbc.port", myConfig.getString("mountwilson.as.db.port", getDatabasePort()));
        prop.put("javax.persistence.jdbc.schema", myConfig.getString("mountwilson.as.db.schema", getDatabaseSchema()));
        prop.put("javax.persistence.jdbc.url" , 
                myConfig.getString("mountwilson.as.db.url",
                myConfig.getString("mtwilson.db.url",
                String.format("jdbc:%s://%s:%s/%s?autoReconnect=true",
                prop.get("javax.persistence.jdbc.scheme"),
                prop.get("javax.persistence.jdbc.host"),
                prop.get("javax.persistence.jdbc.port"),
                prop.get("javax.persistence.jdbc.schema")))));
        prop.put("javax.persistence.jdbc.user",
                myConfig.getString("mountwilson.as.db.user",
                myConfig.getString("mtwilson.db.user",
                "root")));
        prop.put("javax.persistence.jdbc.password", 
                myConfig.getString("mountwilson.as.db.password", 
                myConfig.getString("mtwilson.db.password", 
                "password")));
        prop.put("eclipselink.jdbc.batch-writing", "JDBC");
        
        //log.debug("ASData javax.persistence.jdbc.url={}", prop.getProperty("javax.persistence.jdbc.url"));
        //System.err.println("getJpaProps ASdata url == " + prop.getProperty("javax.persistence.jdbc.url"));
        
        copyDbcpProperties(myConfig, prop);
        
        return prop;
    }    
    
     // copies some properties described in http://commons.apache.org/proper/commons-dbcp/configuration.html
    // using same defaults as shown on that page
    public static void copyDbcpProperties(Configuration myConfig, Properties prop) {
        prop.setProperty("dbcp.max.active", myConfig.getInteger("dbcp.max.active", 8).toString());
        prop.setProperty("dbcp.max.idle", myConfig.getInteger("dbcp.max.idle", 8).toString());
        prop.setProperty("dbcp.min.idle", myConfig.getInteger("dbcp.min.idle", 0).toString()); // can be used instead of initial size
        prop.setProperty("dbcp.validation.query", myConfig.getString("dbcp.validation.query","")); // for example SELECT 1 ; we provide empty string default because Properties would throw NullPointerException for a null value
        prop.setProperty("dbcp.validation.on.borrow",String.valueOf( myConfig.getBoolean("dbcp.validation.on.borrow", true))); 
        prop.setProperty("dbcp.validation.on.return", String.valueOf(myConfig.getBoolean("dbcp.validation.on.return", false))); 
    }
    
    
    ///////////////////////// database //////////////////////////////////
    public static String getDatabaseProtocol() {
        Configuration conf = getConfiguration();
        if (conf.containsKey("mtwilson.db.protocol")) {
            conf.getString("mtwilson.db.protocol", "postgresql");
        }
        if (conf.containsKey("mountwilson.as.db.protocol")) {
            conf.getString("mountwilson.as.db.protocol", "postgresql");
        } 
        if (conf.containsKey("mountwilson.ms.db.protocol")) {
            conf.getString("mountwilson.ms.db.protocol", "postgresql");
        } 
        if (conf.containsKey("mtwilson.db.driver")) {
            String driver = conf.getString("mtwilson.db.driver", "");
            if (driver.equals("org.postgresql.Driver")) {
                return "postgresql";
            }
            if (driver.equals("com.mysql.jdbc.Driver")) {
                return "mysql";
            }
        }
        if (conf.containsKey("mtwilson.db.port")) {
            String port = conf.getString("mtwilson.db.port", "");
            if (port.equals("5432")) {
                return "postgresql";
            }
            if (port.equals("3306")) {
                return "mysql";
            }
        }
        return "postgresql";  // used in the jdbc url, so "postgresql" or "mysql"  as in jdbc:mysql://host:port/schema
    }
    
    public static String getDatabaseDriver() {
        Configuration conf = getConfiguration();
        if (conf.containsKey("mtwilson.db.driver")) {
            conf.getString("mtwilson.db.driver", "org.postgresql.Driver");
        }
        if (conf.containsKey("mountwilson.as.db.driver")) {
            conf.getString("mountwilson.as.db.driver", "org.postgresql.Driver");
        } 
        if (conf.containsKey("mountwilson.ms.db.driver")) {
            conf.getString("mountwilson.ms.db.driver", "org.postgresql.Driver");
        } 
        if (conf.containsKey("mtwilson.db.protocol")) {
            String protocol = conf.getString("mtwilson.db.protocol", "");
            if (protocol.equals("postgresql")) {
                return "org.postgresql.Driver";
            }
            if (protocol.equals("mysql")) {
                return "com.mysql.jdbc.Driver";
            }
        }
        if (conf.containsKey("mtwilson.db.port")) {
            String port = conf.getString("mtwilson.db.port", "");
            if (port.equals("5432")) {
                return "org.postgresql.Driver";
            }
            if (port.equals("3306")) {
                return "com.mysql.jdbc.Driver";
            }
        }
        return "com.mysql.jdbc.Driver"; // either "org.postgresql.Driver" or "com.mysql.jdbc.Driver" // Used to be postgresql, oat mainly supports mysql so changed it
    }

    public static String getDatabasePort() {
        Configuration conf = getConfiguration();
        if (conf.containsKey("mtwilson.db.port")) {
            conf.getString("mtwilson.db.port", "5432");
        }
        if (conf.containsKey("mountwilson.as.db.port")) {
            conf.getString("mountwilson.as.db.port", "5432");
        } 
        if (conf.containsKey("mountwilson.ms.db.port")) {
            conf.getString("mountwilson.ms.db.port", "5432");
        } 
        if (conf.containsKey("mtwilson.db.protocol")) {
            String protocol = conf.getString("mtwilson.db.protocol", "");
            if (protocol.equals("postgresql")) {
                return "5432";
            }
            if (protocol.equals("mysql")) {
                return "3306";
            }
        }
        if (conf.containsKey("mtwilson.db.driver")) {
            String port = conf.getString("mtwilson.db.driver", "");
            if (port.equals("org.postgresql.Driver")) {
                return "5432";
            }
            if (port.equals("com.mysql.jdbc.Driver")) {
                return "3306";
            }
        }
        return "5432"; // 5432 is postgresql default, 3306 is mysql default
    }
    
    public static String getDatabaseHost() {
        return getConfiguration().getString("mtwilson.db.host", "127.0.0.1");
    }

    public static String getDatabaseUsername() {
        return getConfiguration().getString("mtwilson.db.user", ""); // removing default in mtwilson 1.2; was "root"
    }

    public static String getDatabasePassword() {
        return getConfiguration().getString("mtwilson.db.password", getConfiguration().getString("PGPASSWORD", "")); // removing default in mtwilson 1.2;  was "password";   // bug #733 
    }

    public static String getDatabaseSchema() {
        return getConfiguration().getString("mtwilson.db.schema", "mw_as");
    }
    
    /**
     * Caller must close() the connection.
     * @return
     * @throws ClassNotFoundException
     * @throws SQLException 
     */
    public static Connection getConnection() throws ClassNotFoundException, SQLException {
        String driver = getDatabaseDriver();
        //log.debug("JDBC Driver: {}", driver);
        Class.forName(driver);
        Connection c = DriverManager.getConnection(getJpaProperties().getProperty("javax.persistence.jdbc.url"), getDatabaseUsername(), getDatabasePassword());
        return c;
    }
    public static String getAssetTagMtWilsonBaseUrl() {
        Configuration conf = getConfiguration();
        return conf.getString("mtwilson.atag.mtwilson.baseurl", "");
    }
    
    public static String getTagKeystoreUsername() {
        Configuration conf = getConfiguration();
        return conf.getString("mtwilson.tag.api.username");
    }

    public static String getTagKeystorePassword() {
        Configuration conf = getConfiguration();
        return conf.getString("mtwilson.tag.api.password");
    }
    
     public static URL getMtWilsonURL() throws MalformedURLException {
        Configuration conf = getConfiguration();
        return new URL(conf.getString("mtwilson.api.url", conf.getString("mtwilson.api.baseurl", "https://127.0.0.1:8181")));
    }
     
    // use this to instantiate a client  from mtwilson-client-java7-jaxrs2
    public static Properties getClientProperties() throws MalformedURLException {
        Configuration conf = getConfiguration();
        Properties properties = new Properties();
        properties.setProperty("mtwilson.api.url", getMtWilsonURL().toString());
        // x509 authentication
        if (conf.containsKey("mtwilson.api.keystore")) {
            properties.setProperty("mtwilson.api.keystore", conf.getString("mtwilson.api.keystore", getKeystoreFile().getAbsolutePath())); // getKeystoreUsername actually looks at mtwilson.api.username and mtwilson.api.password
            properties.setProperty("mtwilson.api.keystore.password", conf.getString("mtwilson.api.keystore.password", getKeystorePassword()));
            properties.setProperty("mtwilson.api.key.alias", conf.getString("mtwilson.api.key.alias", getKeystoreUsername()));
            properties.setProperty("mtwilson.api.key.password", conf.getString("mtwilson.api.key.password", getKeystorePassword()));
        }
        // hmac authentication
        if (conf.containsKey("mtwilson.api.clientId") && conf.containsKey("mtwilson.api.secretKey")) {
            properties.setProperty("mtwilson.api.clientId", conf.getString("mtwilson.api.clientId"));
            properties.setProperty("mtwilson.api.secretKey", conf.getString("mtwilson.api.secretKey"));
        }
        // basic password authentication
        if (conf.containsKey("mtwilson.api.username") && conf.containsKey("mtwilson.api.password")) {
            properties.setProperty("mtwilson.api.username", conf.getString("mtwilson.api.username"));
            properties.setProperty("mtwilson.api.password", conf.getString("mtwilson.api.password"));

        }
        
        if (conf.containsKey("mtwilson.api.tls.policy.certificate.sha1")) {
            properties.setProperty("mtwilson.api.tls.policy.certificate.sha1", conf.getString("mtwilson.api.tls.policy.certificate.sha1"));
        } else if (conf.containsKey("mtwilson.api.tls.policy.insecure")) {
            properties.setProperty("mtwilson.api.tls.policy.insecure", conf.getString("mtwilson.api.tls.policy.insecure"));
        }
        return properties;
    }
    
    public static File getKeystoreFile() {
        String username = getKeystoreUsername();
        //return new File(getDirectoryPath() + File.separator + username + ".jks");
        return new File(ConfigurationUtil.getConfigurationFolderPath() + File.separator + username + ".jks");
    }
  
    public static String getKeystoreUsername() {
        Configuration conf = getConfiguration();
        return conf.getString("mtwilson.api.username", System.getProperty("user.name", "anonymous"));
    }

    public static String getKeystorePassword() {
        Configuration conf = getConfiguration();
        return conf.getString("mtwilson.api.password");
    }

    
    public static Properties getJpaProperties() {
        Configuration config = getConfiguration();
        Properties prop = new Properties();
        prop.put("javax.persistence.jdbc.driver", 
                config.getString("mountwilson.as.db.driver", 
                config.getString("mtwilson.db.driver",
                "com.mysql.jdbc.Driver")));
        prop.put("javax.persistence.jdbc.url" , 
                config.getString("mountwilson.as.db.url",
                config.getString("mtwilson.db.url",
                String.format("jdbc:mysql://%s:%s/%s?autoReconnect=true",
                    config.getString("mountwilson.as.db.host", config.getString("mtwilson.db.host","127.0.0.1")),
                    config.getString("mountwilson.as.db.port", config.getString("mtwilson.db.port","3306")),
                    config.getString("mountwilson.as.db.schema", config.getString("mtwilson.db.schema","mw_as"))))));
        prop.put("javax.persistence.jdbc.user",
                config.getString("mountwilson.as.db.user",
                config.getString("mtwilson.db.user",
                "root")));
        prop.put("javax.persistence.jdbc.password", 
                config.getString("mountwilson.as.db.password", 
                config.getString("mtwilson.db.password", 
                "password")));
        return prop;
    }
    
    public static int getTrustAgentTimeOutinMilliSecs(){
        // Return timeout in milliseconds
        return getConfiguration().getInt("com.intel.mountwilson.as.trustagent.timeout", 3) * 1000;
    }

    public static int getTrustAgentSleepTimeinMilliSecs(){
        // Return timeout in milliseconds
        return getConfiguration().getInt("com.intel.mtwilson.as.business.trust.sleepTime", 2) * 1000;
    }
    
    public static ASConfig getInstance(){
        return ASConfig.global;
    }
    
    public static File getAssetTagCaCertificateFile() {
        Configuration conf = getConfiguration();
        return findConfigurationFile(conf.getString("mtwilson.tag.cacerts.file", "tag-cacerts.pem"));
    }
    
    private static File findConfigurationFile(String path) {
        File f = new File(path);
        if (f.isAbsolute()) {
            return f;
        } else {
            return new File(ConfigurationUtil.getConfigurationFolderPath() + File.separator + path);
        }
    }
    
    public static String getDataEncryptionKeyBase64() {
        Configuration conf = getConfiguration();
        return conf.getString("mtwilson.as.dek", ""); // removing default in mtwilson 1.2;  was "hPKk/2uvMFRAkpJNJgoBwA=="
    }
    
    public static File getSamlCertificateFile() {
        Configuration conf = getConfiguration();
        return findConfigurationFile(conf.getString("mtwilson.saml.certificate.file", "saml.crt.pem"));
    }

    public static File getSamlKeystoreFile() {
        Configuration conf = getConfiguration();
        return findConfigurationFile(conf.getString("saml.keystore.file", "mtwilson-saml.jks"));
    }

    public static String getSamlKeystorePassword() {
        Configuration conf = getConfiguration();
        return conf.getString("saml.key.password"); // bug #733 
    }
    
    public static String getSamlKeyAlias() {
        Configuration conf = getConfiguration();
        return conf.getString("saml.key.alias"); 
    }
}
