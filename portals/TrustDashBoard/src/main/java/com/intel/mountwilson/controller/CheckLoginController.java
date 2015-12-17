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
 * This Class is use to check login Credential. If login is successful it will redirect user to home page otherwise it will return Login page. 
 */
package com.intel.mountwilson.controller;

import com.intel.mountwilson.common.TDPConfig;
import com.intel.mtwilson.ApiClient;
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

	
	// variable declaration used during Processing data. 
	private static final Logger logger = Logger.getLogger(CheckLoginController.class.getName());
	
        @Override
	protected ModelAndView handleRequestInternal(HttpServletRequest req,HttpServletResponse res) throws Exception {
		logger.info("CheckLoginController >>");
		
		//Creating ModelAndView Object with Login page to return to user if Login is not successful.
		ModelAndView view = new ModelAndView("Login");
		//RsaCredential credential = null;
		File keystoreFile = null;
                SimpleKeystore keystore = null;
		
		String username = "admin";
        
                URL baseURL = new URL(TDPConfig.getConfiguration().getString("mtwilson.api.baseurl")); 

                
                final String keystoreFilename = TDPConfig.getConfiguration().getString("mtwilson.tdbp.keystore.dir") + File.separator +  "portal.jks";
                final String keystorePassword = TDPConfig.getConfiguration().getString("mtwilson.tdbp.keystore.password");
                
		try{
			keystoreFile = new File(keystoreFilename);
                }catch(Exception e){
                        logger.severe("File Not found on server >> "+keystoreFilename);
                        e.printStackTrace();
                        view.addObject("message", "Private key file is missing on server.");
                        return view;
                }
		
                
		try {
                        keystore = new SimpleKeystore(keystoreFile, keystorePassword);
                        //credential = keystore.getRsaCredentialX509(username, keystorePassword);
		} catch (Exception e) {
                    view.addObject("message", "The username or password you entered is incorrect.");
                    return view;
		}
		
		
		try {
			Properties p = new Properties();
                        logger.info("Trust Dashboard: mtwilson.api.ssl.policy="+TDPConfig.getConfiguration().getString("mtwilson.api.ssl.policy"));
                        p.setProperty("mtwilson.api.ssl.policy", TDPConfig.getConfiguration().getString("mtwilson.api.ssl.policy", "TRUST_CA_VERIFY_HOSTNAME")); // must be secure out of the box!
                        p.setProperty("mtwilson.api.ssl.requireTrustedCertificate", TDPConfig.getConfiguration().getString("mtwilson.api.ssl.requireTrustedCertificate", "true")); // must be secure out of the box!
                        p.setProperty("mtwilson.api.ssl.verifyHostname", TDPConfig.getConfiguration().getString("mtwilson.api.ssl.verifyHostname", "true")); // must be secure out of the box!
	     
                        ApiClient rsaApiClient = new ApiClient(baseURL, keystore, new MapConfiguration(p));
                        X509Certificate[] trustedCertificates = new X509Certificate[0]; // keystore.getTrustedCertificates(SimpleKeystore.SAML);
	     
                        //Storing information into a request session. These variables are used in DemoPortalDataController.
                        HttpSession session = req.getSession();
			session.setAttribute("logged-in", true);
			session.setAttribute("username",username);
			session.setAttribute("apiClientObject",rsaApiClient);
			session.setAttribute("trustedCertificates",trustedCertificates);
			session.setMaxInactiveInterval(Integer.parseInt(TDPConfig.getConfiguration().getString("mtwilson.tdbp.sessionTimeOut")));
			
			//if Login is successful, redirecting user to first/Home page.
			res.sendRedirect("home.html");
		} catch (Exception e) {
			view.addObject("message", "The username or password you entered is incorrect.");
			return view;
		}
		return null;
	}
}