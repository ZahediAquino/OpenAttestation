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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mountwilson.common;

import java.io.File;
import java.io.FileNotFoundException;


import org.apache.commons.configuration.Configuration;
import org.slf4j.LoggerFactory;



/**
 *
 * @author dsmagadX
 */
public class Config {
    
    private static Configuration config = TAConfig.getConfiguration();
    private static Config instance = null;
    //private static String appPath = config.getString("app.path"); // System.getProperty("app.path",".");;
    private static Boolean debug;

    private static String homeFolder = "./config";

    public static String getHomeFolder() {
		return homeFolder;
	}


	public static void setHomeFolder(String homeFolder) {
		Config.homeFolder = homeFolder;
	}


	static{
		File propFile;
        homeFolder = "/etc/intel/cloudsecurity";
		try {
            propFile = new File(homeFolder);
            if(!propFile.isDirectory()) {
                propFile.mkdir();
                LoggerFactory.getLogger(Config.class.getName()).warn("Home folder. Using " + homeFolder);
            }
		} catch (Exception e) {
			LoggerFactory.getLogger(Config.class.getName()).error("Could not create the home folder. Using " + homeFolder);
		}
    }
    
    public static boolean isDebug() {
        if( debug == null ) {
            debug =  config.getString("debug").equalsIgnoreCase("true");
        }
        return debug;
    }
    
    
    private Config() {
    }
    
    public static Config getInstance() {
        if(instance == null){
            instance = new Config();
        }
        
        return instance;
    }
    
    public String getProperty(String property){
        if( config.containsKey(property) ) {
            return config.getString(property);
        }
        else {
            LoggerFactory.getLogger(Config.class.getName()).warn("Property {0} missing in config file.", property);
            return "";
        }
    }
    
    
     
    public static String getAppPath(){
        return config.getString("app.path");
    }
    
    
    
    public static String getBinPath() {
        return getAppPath() + File.separator + "bin";
    }
    
    
}
