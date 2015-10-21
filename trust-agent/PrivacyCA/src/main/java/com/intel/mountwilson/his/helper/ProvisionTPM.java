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

package com.intel.mountwilson.his.helper;

import gov.niarl.his.privacyca.TpmClient;
import gov.niarl.his.privacyca.TpmModule;
import gov.niarl.his.privacyca.TpmUtils;
import gov.niarl.his.privacyca.TpmModule.TpmModuleException;
import gov.niarl.his.webservices.hisPrivacyCAWebService2.IHisPrivacyCAWebService2;
import gov.niarl.his.webservices.hisPrivacyCAWebService2.client.HisPrivacyCAWebServices2ClientInvoker;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.cert.CertificateException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;


//import com.intel.mountwilson.as.common.ResourceFinder;
import com.intel.mtwilson.util.ResourceFinder;
import org.apache.commons.codec.binary.Hex;

/**
 * <p>This is part 1 of 3 for fully provisioning HIS on a Windows client. This class does the initial provisioning of the TPM.</p>
 * This provisioning includes:
 * <ul>
 * <li>Taking ownership of the TPM</li>
 * <li>Creating an Endorsement Certificate</li>
 * <li>Storing the Endorsement Certificate in the TPM's NVRAM</li>
 * </ul>
 * 
 * <p>This class utilizes a properties file. It looks for a file by the name of "HISprovisioner.properties" in the directory from which Java was invoked.</p>
 * The following values must be in the properties file:<br>
 * <ul>
 * <li><b>EcValidityDays</b></li>
 * <li><b>TpmOwnerAuth</b> This must be a 40 digit (20 byte) hex code representing the owner auth data to be assigned.</li>
 * </ul>
 * 
 * @author schawki
 *
 */
public class ProvisionTPM {

	private static Logger log = Logger.getLogger(ProvisionTPM.class.getName());

	/**
	 * Entry point into the program
	 * @throws Exception 
	 */
	public static void takeOwnership() throws Exception{// throws InvalidKeyException, CertificateEncodingException, UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, NoSuchProviderException, KeyStoreException, CertificateException, IOException, javax.security.cert.CertificateException {
		//get properties file info
		final String OWNER_AUTH = "TpmOwnerAuth";
		final String EC_VALIDITY = "EcValidityDays";
		final String EC_STORAGE = "ecStorage";
		final String PRIVACY_CA_URL = "PrivacyCaUrl";
		final String TRUST_STORE = "TrustStore";
		final String PRIVACY_CA_CERT = "PrivacyCaCertFile";
		final String EC_LOCATION = "ecLocation";
		String ecStorage = "";
		String ecStorageFileName = "";
		String PrivacyCaUrl = "";
 		int EcValidityDays = 0;
 		String PrivacyCaCertFile = "";
		
		byte [] TpmOwnerAuth = null;
		byte[] encryptCert = null;
		byte [] pubEkMod = null;
		X509Certificate pcaCert = null;
		PublicKey publicKey = null;

		//This is for logging purpose
		String propertiesFileName = ResourceFinder.getLocation("hisprovisioner.properties");

		FileInputStream PropertyFile = null;
		String tpmOwnerAuth = "";
		String homeFolder = "";
		
		try {
			File propFile = ResourceFinder.getFile("hisprovisioner.properties");
			PropertyFile = new FileInputStream(propFile);
			Properties HisProvisionerProperties = new Properties();
			HisProvisionerProperties.load(new InputStreamReader(PropertyFile, "UTF-8"));
			
			
			homeFolder = propFile.getAbsolutePath();
			homeFolder = homeFolder.substring(0,homeFolder.indexOf("hisprovisioner.properties"));
			
			log.info("Home folder : " + homeFolder);
		
			EcValidityDays = Integer.parseInt(HisProvisionerProperties.getProperty(EC_VALIDITY, ""));
			tpmOwnerAuth = HisProvisionerProperties.getProperty(OWNER_AUTH, "");
			if (tpmOwnerAuth != null) {
                            TpmOwnerAuth = Hex.decodeHex(tpmOwnerAuth.toCharArray());
			} 
                        //else if (tpmOwnerAuth.length() == 40) {
			//    log.info("owner authentication is hex code formatted");
			//    TpmOwnerAuth = TpmUtils.hexStringToByteArray(tpmOwnerAuth);
			//} else {
			//    log.info("illegal owner authentication detected! accepted owner authentication is 20 or 40 long characters");
			//}
			//TpmOwnerAuth = TpmUtils.hexStringToByteArray(HisProvisionerProperties.getProperty(OWNER_AUTH, ""));
			PrivacyCaUrl = HisProvisionerProperties.getProperty(PRIVACY_CA_URL, "");
			PrivacyCaCertFile = HisProvisionerProperties.getProperty(PRIVACY_CA_CERT, "");
			ecStorage = HisProvisionerProperties.getProperty(EC_STORAGE, "NVRAM");
			ecStorageFileName = HisProvisionerProperties.getProperty(EC_LOCATION, ".") + System.getProperty("file.separator") + "EC.cer";
			log.info("ecStorageFileName:" + ecStorageFileName);
		} catch (FileNotFoundException e) {
			throw new PrivacyCAException("Error finding HIS Provisioner properties file (HISprovisionier.properties)",e);
		} catch (IOException e) {
			throw new PrivacyCAException("Error loading HIS Provisioner properties file (HISprovisionier.properties)",e);
		} catch (NumberFormatException e) {
			throw new PrivacyCAException("Error while reading EcValidityDays",e);
		}
		finally{
			if (PropertyFile != null){
				try {
					PropertyFile.close();
				} catch (IOException e) {
					log.log(Level.SEVERE,"Error while closing the property file ", e);
				}
			}
		}
		
		String errorString = "Properties file \"" + propertiesFileName + "\" contains errors:\n";
		boolean hasErrors = false;
                if(EcValidityDays == 0){
			errorString += " - \"EcValidityDays\" value must be the number of validity days for the Endorsement Credential\n";
			hasErrors = true;
		}
		if(TpmOwnerAuth == null) {// || TpmOwnerAuth.length != 20){
			errorString += " - \"TpmOwnerAuth\" value must be set representing the TPM owner auth\n";
			hasErrors = true;
		}
		if(hasErrors){
			throw new PrivacyCAException(errorString);
		}
		//Provision the TPM
		log.info("Performing TPM provisioning...");

		Security.addProvider(new BouncyCastleProvider());
		SecretKey deskey = TpmUtils.generateSecretKey();
		// Take Ownership
		byte [] nonce = null;		
		try {
		    nonce = TpmUtils.createRandomBytes(20);
		    TpmModule.takeOwnership(TpmOwnerAuth, nonce);
		} catch (TpmModuleException e){
            if(e.toString().contains(".takeOwnership returned nonzero error: 4")){
                Logger.getLogger(ProvisionTPM.class.getName()).info("Ownership is already taken : " );
                                if( !System.getProperty("forceCreateEk", "false").equals("true") ) { // feature to help with bug #554 and allow admin to force creating an ek (in case it failed the first time due to a non-tpm error such as java missing classes exception
                                    return;
                                }
            }
            else
                throw e;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// Create Endorsement Certificate
		try {
			nonce = TpmUtils.createRandomBytes(20);
			pubEkMod = TpmModule.getEndorsementKeyModulus(TpmOwnerAuth, nonce);
		} catch (TpmModuleException e){
			System.out.println("Error getting PubEK: " + e.toString());
		} catch (Exception e){
			System.out.println("Error getting PubEK: " + e.toString());
		}
		
		try {
			pcaCert = TpmUtils.certFromFile(homeFolder + PrivacyCaCertFile);
			if (pcaCert != null){
			publicKey = (RSAPublicKey)pcaCert.getPublicKey();
			}
		} catch (Exception e){
			System.out.println("print out error message: " + e.toString());
			e.printStackTrace();
 		}
		try {					
			IHisPrivacyCAWebService2 hisPrivacyCAWebService2 = HisPrivacyCAWebServices2ClientInvoker.getHisPrivacyCAWebService2(PrivacyCaUrl);	
			encryptCert = hisPrivacyCAWebService2.requestGetEC(TpmUtils.encryptDES(pubEkMod, deskey), TpmUtils.encryptRSA(deskey.getEncoded(), publicKey), EcValidityDays);	
		} catch (Exception e){
			System.out.println("FAILED");
			e.printStackTrace();
			System.exit(1);
		}
		
		//Decrypt and generate endorsement certificate 
		X509Certificate ekCert = null;		
		try {
			if (encryptCert != null){
				ekCert = TpmUtils.certFromBytes(TpmUtils.decryptDES(encryptCert, deskey));
			}
		} catch (java.security.cert.CertificateException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
			
		// Store the new EC in NV-RAM or in the file
 		try{
 	         if (ecStorage.equalsIgnoreCase("file")){
                 File ecFile = new File(ecStorageFileName);
                 FileOutputStream ecFileOut = new FileOutputStream(ecFile);
                 ecFileOut.write(ekCert.getEncoded());
                 ecFileOut.flush();
                 ecFileOut.close();
             } else {
                 TpmModule.setCredential(TpmOwnerAuth, "EC", ekCert.getEncoded());
             }
 			System.out.println( ekCert.getEncoded().length);
 		} catch (TpmModuleException e){
 			System.out.println("Error getting PubEK: " + e.toString());
 		} catch (CertificateEncodingException e) {
 			e.printStackTrace();
 		} catch (IOException e) {
 			e.printStackTrace();
 		}
		System.out.println("DONE");
		//System.exit(0);
		return;
 	}
        
}
