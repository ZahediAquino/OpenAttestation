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

/**
 * This class is used to check username and password while login.
 */
package com.intel.mountwilson.controller;

import com.intel.mountwilson.common.WLMPConfig;
import com.intel.mountwilson.common.WLMPPersistenceManager;
import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.as.controller.MwKeystoreJpaController;
import com.intel.mtwilson.util.crypto.SimpleKeystore;
import java.io.File;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.configuration.MapConfiguration;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

/**
 * @author yuvrajsx
 *
 */
public class CheckLoginController extends AbstractController {

	
	// variable declaration used for logging. 
	private static final Logger logger = Logger.getLogger(CheckLoginController.class.getName());
	private WLMPPersistenceManager wlmManager = new WLMPPersistenceManager();
	private MwKeystoreJpaController keystoreJpa = new MwKeystoreJpaController(wlmManager.getEntityManagerFactory("ASDataPU"));
        
	@Override
	protected ModelAndView handleRequestInternal(HttpServletRequest req,HttpServletResponse res) throws Exception {
		logger.info("CheckLoginController >>");
		
		//Creating ModelAndView Object with Login page to return to user if Login is not successful.
		ModelAndView view = new ModelAndView("Login");
		//RsaCredential credential = null;
                File keystoreFile = null;
                SimpleKeystore keystore = null;
		
		String username = "admin";

		URL baseURL = new URL(WLMPConfig.getConfiguration().getString("mtwilson.api.baseurl"));  
                
		final String keystoreFilename = WLMPConfig.getConfiguration().getString("mtwilson.wlmp.keystore.dir") + File.separator +  "portal.jks";
                final String keystorePassword = WLMPConfig.getConfiguration().getString("mtwilson.wlmp.keystore.password");
                
		try{
                    //this line will throw exception if file with username is not present in specific dir.
                    keystoreFile = new File(keystoreFilename);
                    
                }catch(Exception e){
                    logger.severe("File Not found on server >> "+keystoreFilename);
                    view.addObject("message", "Key store is not configured/saved correctly in " + keystoreFilename + ".");
                    return view;
                }
                
               		
		try {
                    keystore = new SimpleKeystore(keystoreFile, keystorePassword);
                    //credential = keystore.getRsaCredentialX509(username, keystorePassword);
		} catch (Exception e) {
                        view.addObject("result", false);
			view.addObject("message", "Username or Password does not match. Please try again.");
			return view;
		}
		
		
		try {
                    Properties p = new Properties();
                    p.setProperty("mtwilson.api.ssl.policy", WLMPConfig.getConfiguration().getString("mtwilson.api.ssl.policy", "TRUST_CA_VERIFY_HOSTNAME")); // must be secure out of the box!
                    p.setProperty("mtwilson.api.ssl.requireTrustedCertificate", WLMPConfig.getConfiguration().getString("mtwilson.api.ssl.requireTrustedCertificate", "true")); // must be secure out of the box!
                    p.setProperty("mtwilson.api.ssl.verifyHostname", WLMPConfig.getConfiguration().getString("mtwilson.api.ssl.verifyHostname", "true")); // must be secure out of the box!
	 
                    // Instantiate the API Client object and store it in the session. Otherwise either we need
                    // to store the password in the session or the decrypted RSA key
                    ApiClient rsaApiClient = new ApiClient(baseURL, keystore, new MapConfiguration(p));
	      
                    //Storing variable into a session object used while calling into RESt Services.
                    HttpSession session = req.getSession();
                    session.setAttribute("logged-in", true);
                    session.setAttribute("username",username);
                    session.setAttribute("apiClientObject",rsaApiClient);
                    session.setMaxInactiveInterval(WLMPConfig.getConfiguration().getInt("mtwilson.wlmp.sessionTimeOut"));
                    
                    X509Certificate[] trustedCertificates = keystore.getTrustedCertificates(SimpleKeystore.SAML);
                    
                    session.setAttribute("trustedCertificates",trustedCertificates);
                    
	        
                    //Redirecting user to a home page after successful login.
                    res.sendRedirect("home.html");
             
		} catch (Exception e) {
			view.addObject("message", "The username or password you entered is incorrect.");
			return view;
		}
		return null;
	}
}
