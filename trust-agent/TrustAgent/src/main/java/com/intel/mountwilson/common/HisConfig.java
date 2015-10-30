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

package com.intel.mountwilson.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Properties;
import org.apache.commons.configuration.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Attempts to use commons-configuration to load the Trust Agent settings.
 * 
 * The configuration is loaded in the following priority order:
 * System properties
 * Properties in the file trustagent.properties (create this file in your classpath to customize local settings)
 * Hard-coded defaults (defined in this class)
 * 
 * The available configuration sources (such as trustagent.properties) are configured in the ta-config.xml
 * included with Trust Agent
 * 
 * @author jbuhacoff
 */
public class HisConfig {

    private static final HisConfig global = new HisConfig();
    public static final Configuration getConfiguration() { return global.getConfigurationInstance(); }
    
    private final Configuration config;
    private Configuration getConfigurationInstance() { return config; }
    private Logger log = LoggerFactory.getLogger(getClass().getName());
    
    private HisConfig() {
        Properties defaults = new Properties();
        String propertiesFilename = "hisprovisioner.properties";
        try{
            InputStream in = new FileInputStream(Config.getHomeFolder()+"/"+propertiesFilename);		
            if (in != null) {
                    try {
                            Properties properties = new Properties();
                            properties.load(in);
                            defaults.setProperty("HisIdentityAuth", properties.get("HisIdentityAuth").toString());
                    } finally {
                            in.close();
                    }
            }
            else
                defaults.setProperty("HisIdentityAuth", "1212121212121212121212121212121212121212");
        }
        catch(IOException e)
        {
            log.info("Error encountered while loading HisIdentityAuth, will use default value instead. Error: {}",e);        
            defaults.setProperty("HisIdentityAuth", "1212121212121212121212121212121212121212");
        }
        log.info("HisIdentityAuth was set to: "+defaults.get("HisIdentityAuth").toString());        
        config = gatherConfiguration("hisprovisioner.properties", defaults);
    }
    
    // for troubleshooting
    private void dumpConfiguration(Configuration c, String label) {
        String keys[] = new String[] { "app.path", "debug", "secure.port", "nonsecure.port" };
        for(String key : keys) {
            String value = c.getString(key);
            System.out.println(String.format("TAConfig [%s]: %s=%s", label, key, value));
        }
    }

	private void readPropertiesFile(String propertiesFilename,
			CompositeConfiguration composite) throws IOException {
		InputStream in = getClass().getResourceAsStream(propertiesFilename);
		log.info("Reading property file " +  propertiesFilename);
		if (in != null) {
			try {
				Properties properties = new Properties();
				properties.load(in);
				MapConfiguration classpath = new MapConfiguration(properties);
				dumpConfiguration(classpath, "classpath:/" + propertiesFilename);
				composite.addConfiguration(classpath);
			} finally {
				in.close();
			}
		}

	}

    private Configuration gatherConfiguration(String propertiesFilename, Properties defaults) {
        CompositeConfiguration composite = new CompositeConfiguration();

        // first priority are properties defined on the current JVM (-D switch or through web container)
        SystemConfiguration system = new SystemConfiguration();
        dumpConfiguration(system, "system");
        composite.addConfiguration(system);

        // second priority are properties defined on the classpath (like user's home directory)        
        try {
            // user's home directory (assuming it's on the classpath!)
            readPropertiesFile("/"+propertiesFilename, composite);
        } catch (IOException ex) {
            log.error("Did not find "+propertiesFilename+" on classpath", ex);
        }
        
        // third priority are properties defined in standard install location
        System.out.println("TAConfig os.name="+System.getProperty("os.name"));
        ArrayList<File> files = new ArrayList<File>();
        // windows-specific location
        if( System.getProperty("os.name", "").toLowerCase().equals("win") ) {
            System.out.println("TAConfig user.home="+System.getProperty("user.home"));
            files.add(new File("C:"+File.separator+"Intel"+File.separator+"CloudSecurity"+File.separator+propertiesFilename));
            files.add(new File(System.getProperty("user.home")+File.separator+propertiesFilename));
        }
        // linux-specific location
        if( System.getProperty("os.name", "").toLowerCase().equals("linux") || System.getProperty("os.name", "").toLowerCase().equals("unix") ) {
            files.add(new File("/etc/oat-client/"+propertiesFilename));
        }
        files.add(new File(System.getProperty("app.path")+File.separator+propertiesFilename)); // this line specific to TA for backwards compatibility, not needed in AS/AH
        // add all the files we found
        for(File f : files) {
            try {
                if( f.exists() && f.canRead() ) {
                    PropertiesConfiguration standard = new PropertiesConfiguration(f);
                    dumpConfiguration(standard, "file:"+f.getAbsolutePath());
                    composite.addConfiguration(standard);
                }
            } catch (ConfigurationException ex) {
                log.error( null, ex);
            }
        }

        // last priority are the defaults that were passed in, we use them if no better source was found
        if( defaults != null ) {
            MapConfiguration defaultconfig = new MapConfiguration(defaults);
            dumpConfiguration(defaultconfig, "default");
            composite.addConfiguration(defaultconfig);
        }
        dumpConfiguration(composite, "composite");
        return composite;
    }
}
