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

package com.intel.mountwilson.manifest.helper;

import java.io.*;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.regex.Pattern;

import com.intel.mtwilson.agent.*;
import com.intel.mtwilson.tls.*;
import com.intel.mtwilson.util.ResourceFinder;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;

import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mountwilson.as.helper.CommandUtil;
import com.intel.mountwilson.as.helper.TrustAgentSecureClient;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mountwilson.ta.data.ClientRequestType;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.datatypes.ErrorCode;

import java.util.ArrayList;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import org.bouncycastle.openssl.PEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bouncycastle.openssl.PEMReader;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author dsmagadx
 * @author dave chen
 */
public class TAHelper {
    private static final Logger log = LoggerFactory.getLogger(TAHelper.class);

    private String aikverifyhome;
    //private String aikverifyhomeData;
    //private String aikverifyhomeBin;
    //private String opensslCmd;
    //private String aikverifyCmd;
    
    private Pattern pcrNumberPattern = Pattern.compile("[0-9]|[0-1][0-9]|2[0-3]"); // integer 0-23 with optional zero-padding (00, 01, ...)
    private Pattern pcrValuePattern = Pattern.compile("[0-9a-fA-F]{40}"); // 40-character hex string
    private String pcrNumberUntaint = "[^0-9]";
    private String pcrValueUntaint = "[^0-9a-fA-F]";
//	private EntityManagerFactory entityManagerFactory;

   private String trustedAik = null; // host's AIK in PEM format, for use in verifying quotes (caller retrieves it from database and provides it to us)
   
   public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
   public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

   
    public TAHelper(/*EntityManagerFactory entityManagerFactory*/) {
        Configuration config = ASConfig.getConfiguration();
        aikverifyhome = config.getString("com.intel.mountwilson.as.home", "C:/work/aikverifyhome");
        //aikverifyhomeData = aikverifyhome+File.separator+"data";
        //aikverifyhomeBin = aikverifyhome+File.separator+"bin";
        //opensslCmd = aikverifyhomeBin + File.separator + config.getString("com.intel.mountwilson.as.openssl.cmd", "openssl.bat");
        //aikverifyCmd = aikverifyhomeBin + File.separator + config.getString("com.intel.mountwilson.as.aikqverify.cmd", "aikqverify.exe");
        
//        boolean foundAllRequiredFiles = true;
//        String required[] = new String[] { aikverifyhome, };
//        for(String filename : required) {
//            File file = new File(filename);
//            if( !file.exists() ) {
//                log.error( String.format("Invalid service configuration: Cannot find %s", filename ));
//                foundAllRequiredFiles = false;
//            }
//        }
//        if( !foundAllRequiredFiles ) {
//            throw new ASException(ErrorCode.AS_CONFIGURATION_ERROR, "Cannot find aikverify files");
//        }
        
        // we must be able to write to the data folder in order to save certificates, nonces, public keys, etc.
        File datafolder = new File(aikverifyhome);
        if( !datafolder.exists() ) {
            throw new ASException(ErrorCode.AS_CONFIGURATION_ERROR, String.format("Cannot find aikverify home: %s", aikverifyhome));
        }
        if( !datafolder.canWrite() ) {
            throw new ASException(ErrorCode.AS_CONFIGURATION_ERROR, String.format(" Cannot write to %s", aikverifyhome));
        }
        
//        this.setEntityManagerFactory(entityManagerFactory);
    }

    public void setTrustedAik(String pem) {
        trustedAik = pem;
    }	

    // BUG #497 see  the other getQuoteInformationForHost which is called from IntelHostAgent
//    public HashMap<String, PcrManifest> getQuoteInformationForHost(String hostIpAddress, String pcrList, String name, int port) {
    public HashMap<String, PcrManifest> getQuoteInformationForHost(TblHosts tblHosts, String pcrList) {
            
          try {
              // going to IntelHostAgent directly because 1) we are TAHelper so we know we need intel trust agents,  2) the HostAgent interface isn't ready yet for full generic usage,  3) one day this entire function will be in the IntelHostAgent or that agent will call THIS function instaed of the othe way around
              HostAgentFactory factory = new HostAgentFactory();
              TlsPolicy tlsPolicy = factory.getTlsPolicy(tblHosts.getTlsPolicyName(), tblHosts.getTlsKeystoreResource());
              
        String connectionString = tblHosts.getAddOnConnectionInfo();
        if( connectionString == null || connectionString.isEmpty() ) {
            if( tblHosts.getIPAddress() != null  ) {
                connectionString = String.format("https://%s:%d", tblHosts.getIPAddress(), tblHosts.getPort()); // without vendor scheme because we are passing directly to TrustAgentSEcureClient  (instead of to HOstAgentFactory)
                log.debug("getQuoteInformationForHost called with ip address and port {}", connectionString);
            }
        }
        else if( connectionString.startsWith("intel:") ) {
            log.debug("getQuoteInformationForHost called with intel connection string: {}", connectionString);
            connectionString = connectionString.substring(6);
        }        
              
              
            TrustAgentSecureClient client = new TrustAgentSecureClient(new TlsConnection(connectionString, tlsPolicy));
//                IntelHostAgent agent = new IntelHostAgent(client, new InternetAddress(tblHosts.getIPAddress().toString()));
                
            
            HashMap<String, PcrManifest> pcrMap = getQuoteInformationForHost( tblHosts.getIPAddress(), client,  pcrList);

            return pcrMap;
            
        } catch (ASException e) {
            throw e;
        } catch(UnknownHostException e) {
            throw new ASException(e,ErrorCode.AS_HOST_COMMUNICATION_ERROR, "Unknown host: "+(tblHosts.getIPAddress()==null?"missing IP Address":tblHosts.getIPAddress().toString()));
        }  catch (Exception e) {
            throw new ASException(e);
        }
    }
    
    public HashMap<String, PcrManifest> getQuoteInformationForHost(String hostname, TrustAgentSecureClient client, String pcrList) throws Exception {
              //  XXX BUG #497  START CODE SNIPPET MOVED TO INTEL HOST AGENT   
            String nonce = generateNonce();

            String sessionId = generateSessionId();

            ClientRequestType clientRequestType = client.getQuote(nonce, pcrList);
            log.info( "got response from server ["+hostname+"] "+clientRequestType);

            String quote = clientRequestType.getQuote();
            log.info( "extracted quote from response: "+quote);

            saveQuote(quote, sessionId);
            log.info( "saved quote with session id: "+sessionId);
			
            // we only need to save the certificate when registring the host ... when we are just getting a quote we need to verify it using the previously saved AIK.
            if( trustedAik == null ) {
                String aikCertificate = clientRequestType.getAikcert();            
                log.info( "extracted aik cert from response: "+aikCertificate);
            
                saveCertificate(aikCertificate, sessionId); 
                log.info( "saved host-provided AIK certificate with session id: "+sessionId);
            }
            else {
                saveCertificate(trustedAik, sessionId); // XXX we only need to save the certificate when registring the host ... when we are just getting a quote we don't need it            
                log.info( "saved database-provided trusted AIK certificate with session id: "+sessionId);                
            }
            
            
            saveNonce(nonce,sessionId);
            
            log.info( "saved nonce with session id: "+sessionId);
            
            createRSAKeyFile(sessionId);

            log.info( "created RSA key file for session id: "+sessionId);
            
            HashMap<String, PcrManifest> pcrMap = verifyQuoteAndGetPcr(sessionId);
            
            log.info( "Got PCR map");
            //log.log(Level.INFO, "PCR map = "+pcrMap); // need to untaint this first
            
            return pcrMap;
        
    }

    // hostName == internetAddress.toString() or Hostname.toString() or IPAddress.toString()
    // vmmName == tblHosts.getVmmMleId().getName()
    public String getHostAttestationReport(String hostName, HashMap<String, PcrManifest> pcrManifestMap, String vmmName) throws Exception {
        XMLOutputFactory xof = XMLOutputFactory.newInstance();
        XMLStreamWriter xtw;
        StringWriter sw = new StringWriter();
        
        /*
            // We need to check if the host supports TPM or not. Only way we can do it
            // using the host table contents is by looking at the AIK Certificate. Based
            // on this flag we generate the attestation report.
            boolean tpmSupport = true;
            String hostType = "";

            if (tblHosts.getAIKCertificate() == null || tblHosts.getAIKCertificate().isEmpty()) {
                tpmSupport = false;
            }
            * */
        boolean tpmSupport = true;  // XXX   assuming it supports TPM since it's trust agent and we got a pcr manifest (which we only get from getQuoteInformationFromHost if the tpm quote was verified, which means we saved the AIK certificate when we did that)


            // xtw = xof.createXMLStreamWriter(new FileWriter("c:\\temp\\nb_xml.xml"));
            xtw = xof.createXMLStreamWriter(sw);
            xtw.writeStartDocument();
            xtw.writeStartElement("Host_Attestation_Report");
            xtw.writeAttribute("Host_Name", hostName);
            xtw.writeAttribute("Host_VMM", vmmName);
            xtw.writeAttribute("TXT_Support", String.valueOf(tpmSupport));

            if (tpmSupport == true) {
                ArrayList<IManifest> pcrMFList = new ArrayList<IManifest>();
                pcrMFList.addAll(pcrManifestMap.values());

                for (IManifest pcrInfo : pcrMFList) {
                    PcrManifest pInfo = (PcrManifest) pcrInfo;
                    xtw.writeStartElement("PCRInfo");
                    xtw.writeAttribute("ComponentName", String.valueOf(pInfo.getPcrNumber()));
                    xtw.writeAttribute("DigestValue", pInfo.getPcrValue().toUpperCase());
                    xtw.writeEndElement();
                }
            } else {
                xtw.writeStartElement("PCRInfo");
                xtw.writeAttribute("Error", "Host does not support TPM.");
                xtw.writeEndElement();
            }

            xtw.writeEndElement();
            xtw.writeEndDocument();
            xtw.flush();
            xtw.close();
            
            String attestationReport = sw.toString();        
            return attestationReport;
    }
    
    public String generateNonce() {
        try {
            // Create a secure random number generator
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            // Get 1024 random bits
            byte[] bytes = new byte[16];
            sr.nextBytes(bytes);

//            nonce = new BASE64Encoder().encode( bytes);
            String nonce = Base64.encodeBase64String(bytes);

            log.info( "Nonce Generated {}", nonce);
            return nonce;
        } catch (NoSuchAlgorithmException e) {
            throw new ASException(e);
        }
    }

    private String generateSessionId() throws NoSuchAlgorithmException  {
        
        // Create a secure random number generator
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
            // Get 1024 random bits
            byte[] seed = new byte[1];
            sr.nextBytes(seed);

            sr = SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed(seed);
            
            

            int nextInt = sr.nextInt();
            String sessionId = "" + ((nextInt < 0)?nextInt *-1 :nextInt); 


            log.info( "Session Id Generated [{}]", sessionId);

        

        return sessionId;

    }
    

    private String getNonceFileName(String sessionId) {
        return "nonce_" + sessionId +".data";
    }

    private String getQuoteFileName(String sessionId) {
        return "quote_" + sessionId +".data";
    }

    private void saveCertificate(String aikCertificate, String sessionId) throws IOException  {
        // first get a consistent newline character
        aikCertificate = aikCertificate.replace('\r', '\n').replace("\n\n", "\n");
	
        if( aikCertificate.indexOf("-----BEGIN CERTIFICATE-----\n") < 0 && aikCertificate.indexOf("-----BEGIN CERTIFICATE-----") >= 0 ) {
            log.info( "adding newlines to certificate BEGIN tag");            
            aikCertificate = aikCertificate.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n");
        }
        if( aikCertificate.indexOf("\n-----END CERTIFICATE-----") < 0 && aikCertificate.indexOf("-----END CERTIFICATE-----") >= 0 ) {
            log.info( "adding newlines to certificate END tag");            
            aikCertificate = aikCertificate.replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");
        }

        saveFile(getCertFileName(sessionId), aikCertificate.getBytes());


    }

    private String getCertFileName(String sessionId) {
        return "aikcert_" + sessionId + ".cer";
    }

    private void saveFile(String fileName, byte[] contents) throws IOException  {
        FileOutputStream fileOutputStream = null;

        try {
            assert aikverifyhome != null;
            log.info( String.format("saving file %s to [%s]", fileName, aikverifyhome));
            fileOutputStream = new FileOutputStream(aikverifyhome + File.separator +fileName);
            assert fileOutputStream != null;
            assert contents != null;
            fileOutputStream.write(contents);
            fileOutputStream.flush();
        }
        catch(FileNotFoundException e) {
            log.info( String.format("cannot save to file %s in [%s]: %s", fileName, aikverifyhome, e.getMessage()));
            throw e;
        } finally {
                 try {
                    fileOutputStream.close();
                } catch (IOException ex) {
                    log.error(String.format("Cannot close file %s in [%s]: %s", fileName, aikverifyhome, ex.getMessage()), ex);
                }
        }


    }

    private void saveQuote(String quote, String sessionId) throws IOException  {
//          byte[] quoteBytes = new BASE64Decoder().decodeBuffer(quote);
        byte[] quoteBytes = Base64.decodeBase64(quote);
          saveFile(getQuoteFileName(sessionId), quoteBytes);
    }

    private void saveNonce(String nonce, String sessionId) throws IOException  {
//          byte[] nonceBytes = new BASE64Decoder().decodeBuffer(nonce);
        byte[] nonceBytes = Base64.decodeBase64(nonce);
          saveFile(getNonceFileName(sessionId), nonceBytes);
    }

    private void createRSAKeyFile(String sessionId)
            throws KeyStoreException,
            IOException,
            NoSuchAlgorithmException,
            javax.security.cert.CertificateException,
            java.security.cert.CertificateException
    {
        X509Certificate cert = certFromFile(aikverifyhome + File.separator + getCertFileName(sessionId));
        FileWriter fw = new FileWriter(aikverifyhome + File.separator + getRSAPubkeyFileName(sessionId));
        PEMWriter pemWriter = new PEMWriter(fw);
        pemWriter.writeObject(cert.getPublicKey());
        pemWriter.flush();
        fw.flush();
        pemWriter.close();
        fw.close();
    }

    private String getRSAPubkeyFileName(String sessionId) {
        return "rsapubkey_" + sessionId + ".key";
    }

    // BUG #497 need to rewrite this to return List<Pcr> ... the Pcr.equals()  does same as (actually more than) IManifest.verify() because Pcr ensures the index is the same and IManifest does not!  and also it is less redundant, because this method returns Map< pcr index as string, manifest object containing pcr index and value >  
    private HashMap<String,PcrManifest> verifyQuoteAndGetPcr(String sessionId) {
        //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        HashMap<String,PcrManifest> pcrMp = new HashMap<String,PcrManifest>();
        String setUpFile;

        log.info( "verifyQuoteAndGetPcr for session {}",sessionId);
        //log.info( "Command: {}",command);
        //List<String> result = CommandUtil.runCommand(command,true,"VerifyQuote");
        String certFileName = aikverifyhome + File.separator + getCertFileName(sessionId);
        //need verify AIC here by the privacyCA's public key
        //1. get privacy CA's public key
        //2. verification
        try {
                setUpFile = ResourceFinder.getFile("attestation-service.properties").getAbsolutePath();
                String fileLocation = setUpFile.substring(0, setUpFile.indexOf("attestation-service.properties"));
                String PrivacyCaCertFileName = "PrivacyCA.cer";
                //X509Certificate machineCertificate = pemToX509Certificate(certFileName);
                X509Certificate machineCertificate = certFromFile(certFileName);
                X509Certificate pcaCert = certFromFile(fileLocation + PrivacyCaCertFileName);
                if (pcaCert !=null)
                    machineCertificate.verify(pcaCert.getPublicKey());
                log.info("passed the verification");
        } catch (Exception e){
            log.error("Machine certificate was not signed by the privacy CA." + e.toString());
            throw new RuntimeException(e);
        }
        String nonceFileName = aikverifyhome + File.separator+getNonceFileName(sessionId);
        String quoteFileName = aikverifyhome + File.separator+getQuoteFileName(sessionId);
        String rsaPubkeyFileName = aikverifyhome + File.separator+getRSAPubkeyFileName(sessionId);
        List<String> result = aikqverify(nonceFileName, rsaPubkeyFileName, quoteFileName);
        // Sample output from command:
        //  1 3a3f780f11a4b49969fcaa80cd6e3957c33b2275
        //  17 bfc3ffd7940e9281a3ebfdfa4e0412869a3f55d8
        //log.log(Level.INFO, "Result - {0} ", result); // need to untaint this first
        
        //List<String> pcrs = getPcrsList(); // replaced with regular expression that checks 0-23
        
        for(String pcrString: result){
            String[] parts = pcrString.trim().split(" ");
            if( parts.length == 2 ) {
                String pcrNumber = parts[0].trim().replaceAll(pcrNumberUntaint, "").replaceAll("\n", "");
                String pcrValue = parts[1].trim().replaceAll(pcrValueUntaint, "").replaceAll("\n", "");
                boolean validPcrNumber = pcrNumberPattern.matcher(pcrNumber).matches();
                boolean validPcrValue = pcrValuePattern.matcher(pcrValue).matches();
                if( validPcrNumber && validPcrValue ) {
                	log.info("Result PCR "+pcrNumber+": "+pcrValue);
                	pcrMp.put(pcrNumber, new PcrManifest(Integer.parseInt(pcrNumber),pcrValue));            	
                }            	
            }
            else {
            	log.warn( "Result PCR invalid");
            }
        }
        
        return pcrMp;
        
    }

    public static List<String> aikqverify(String nonceFileName, String rsaPubkeyFileName, String quoteFileName){
        PublicKey publicKey = getPemPublicKey(rsaPubkeyFileName);
        List<String> pcrList = new ArrayList<String>();
        StringBuffer pcrBuffer;
        try {
            /* Read challenge file */
            byte[] nonce = readFromFile(nonceFileName);
            byte[] chalmd = sha1hash1(nonce);
            /* Read quote file */
            byte[] quote =  readFromFile(quoteFileName);
            /* Parse quote file */
            if (quote.length <2){
                log.error("Input AIK quote file incorrect format\n");
            }
            //concat two bytes to get the select length, x86 use little endian, "0x0003" is stored as "0x0300" in memory
            int selectLen = ntohs(quote, 0);
            int length = quote.length;
            int pcrLen = ntohl(quote, 2 + selectLen);
            int sigPostition = 2 + selectLen + 4 + pcrLen;
            int pcri = 0;
            int sigLen = length - sigPostition;
            byte [] select = new byte[quote.length -2];
            byte[] qinfo = new byte[8+20+20];
            byte[] sig = new byte[sigLen];
            byte[] pcrs;
            qinfo[0] = 1; 
            qinfo[1] = 1; 
            qinfo[2] = 0; 
            qinfo[3] = 0;
            qinfo[4] = 'Q'; 
            qinfo[5] = 'U'; 
            qinfo[6] = 'O'; 
            qinfo[7] = 'T';
            //sha1
            sha1hash2(quote, 2+selectLen+4+pcrLen, qinfo);
            //memcpy
            System.arraycopy(chalmd, 0, qinfo, 8+20, 20);
            /* Verify RSA signature */
            //this step is needn't, the SHA-1 is suspect performed by the java API itself which is different with API from openssl
            //byte[] md = sha1hash1(qinfo);    
            //verify 
            System.arraycopy(quote, sigPostition, sig, 0 , sigLen);
            System.arraycopy(quote, 2, select, 0, select.length);
            pcrs = new byte[quote.length - (2 + selectLen + 4)];
            System.arraycopy(quote, 2 + selectLen + 4, pcrs, 0, pcrs.length);
            Signature signature;
            signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publicKey);
            signature.update(qinfo);
            if (!signature.verify(sig)) {
                log.error("signature is not correct\n");
            } else {
                log.info("signature is correct\n");
            }
            for (int pcr=0; pcr < 8*selectLen; pcr++) {
                if ((select[pcr/8] & (1 << (pcr%8))) != 0) {
                    log.info("pcr number is: " + pcr);
                    pcrBuffer = new StringBuffer();
                    pcrBuffer.append(pcr).append(" ");
                    for (int i=0; i<20; i++) {
                        pcrBuffer.append(hexString(pcrs[20*pcri+i]));
                    }
                    pcrList.add(pcrBuffer.toString());
                    pcri++;
                }
            }
        } catch(IOException e){
            log.error("Unable to read nonce file");
        } catch (NoSuchAlgorithmException e) {
            log.error("no such algorithm " + e.toString());
        } catch (InvalidKeyException e) {
            log.error("invalid key is found " + e.toString());
        } catch (SignatureException e) {
            log.error("signature exception " + e.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
        String resultForLog = pcrList.size()+" items:\n"+StringUtils.join(pcrList, "\n");
        log.info("Result Output \n{}", resultForLog);
        return pcrList;
    }

    public static byte[] readFromFile(String filename)throws IOException{  
        File f = new File(filename);
        if(!f.exists()){  
            throw new FileNotFoundException(filename);  
        }  
          
        FileChannel channel = null;  
        FileInputStream fis = null;  
        try{  
            fis = new FileInputStream(f);  
            channel = fis.getChannel();  
            ByteBuffer byteBuffer = ByteBuffer.allocate((int)channel.size());  //may needn't convert from NBO to HBO as we use ByteBuffer here.
            channel.read(byteBuffer); 
            return byteBuffer.array();  
        }catch (IOException e) {  
            e.printStackTrace();  
            throw e;  
        }finally{  
            try{  
                channel.close();  
            }catch (IOException e) {  
                e.printStackTrace();  
            }  
            try{  
                fis.close();  
            }catch (IOException e) {  
                e.printStackTrace();  
            }  
        }  
    } 
    
    public static byte[] sha1hash1(byte[] blob) throws NoSuchAlgorithmException{
        byte[] toReturn = null;
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        //md.update(blob);
        toReturn = md.digest(blob);
        return toReturn;
    }
    
    public static void sha1hash2(byte[] blob, int length, byte[] qinfo) throws NoSuchAlgorithmException{
        byte[] tempArray = null;
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(blob, 0, length);
        tempArray = md.digest();
        System.arraycopy(tempArray, 0, qinfo, 8, tempArray.length);
    }
   
    public static String hexString(byte byteVaue) {
        Integer integer = byteVaue < 0 ? byteVaue + 256 : byteVaue;
        String integerString = Integer.toString(integer, 16);
        String hexValue = (integerString.length() == 1 ? "0" + integerString : integerString);
        return hexValue.toUpperCase();  
    }
    
    public static int ntohs(byte[] x, int pos)
    {
        int res = 0;
        int size = pos + 2;
        while (pos < size) {
            res <<= 8;
            res |= (int) x[pos] & 0xFF;
            pos ++;
        }
        return res;
    }
    
    public static int ntohl(byte[] x, int pos)
    {
        int res = 0;
        int size = pos + 4;
        while (pos < size){
            res <<= 8;
            res |= (int) x[pos] & 0xFF;
            pos ++;
        }
        return res;
    }
    
    public  static PublicKey getPemPublicKey(String filename){
        File f = new File(filename);
        FileInputStream filestr = null;
        PublicKey pubkey = null;  
        try {
            filestr = new FileInputStream(f);
            DataInputStream datastr = new DataInputStream(filestr);
            byte[] keyBytes = new byte[(int) f.length()];
            datastr.readFully(keyBytes);
            datastr.close();
            String temp = new String(keyBytes);
            String publicKeyPEM = temp.replace("-----BEGIN PUBLIC KEY-----\n", "");
            publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
            Base64 b64 = new Base64();
            byte [] decoded = b64.decode(publicKeyPEM);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            kf.generatePublic(spec);
            pubkey = kf.generatePublic(spec);
       }catch (FileNotFoundException e) {
           log.error("Unable to find rsapubkey file, "+e.toString());
       }catch (IOException e) {
           log.error("Unable to read nonce file");
       }catch (NoSuchAlgorithmException e) {
           log.error("no such algorithm " + e.toString());
       }catch (InvalidKeySpecException e) {
           log.error("invalid key is found " + e.toString());
       }
       return pubkey;
    }
    
    /**
     * Convert a PEM formatted certificate in X509 format.
     * @param machineCertPEM Machine certificate in PEM/text format. 
     * @return An X509 certificate object.
     */
    public static X509Certificate pemToX509Certificate(String machineCertPEM) {
        try {
            File f = new File(machineCertPEM);
            FileInputStream filestr = new FileInputStream(f);
            DataInputStream datastr = new DataInputStream(filestr);
            byte[] keyBytes = new byte[(int) f.length()];
            datastr.readFully(keyBytes);
            String temp = new String(keyBytes);
            PEMReader reader = new PEMReader(new StringReader(temp.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n").replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----")));
            datastr.close();
            return (X509Certificate) reader.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Retrieve a certificate as an X509Certificate object from a file (generally .cer or .crt using DER or PEM encoding)
     * @param filename
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws javax.security.cert.CertificateException
     * @throws java.security.cert.CertificateException
     */
    public static X509Certificate certFromFile(String filename)
            throws KeyStoreException,
            IOException,
            NoSuchAlgorithmException,
            javax.security.cert.CertificateException,
            java.security.cert.CertificateException {
        InputStream certStream = new FileInputStream(filename);
//      byte [] certBytes = new byte[certStream.available()];
        byte[] certBytes = new byte[2048];
        try {
            int k = certStream.read(certBytes);

//      } catch (Exception e) {
//          e.printStackTrace();
        }
        finally{
                 certStream.close();
        }
        javax.security.cert.X509Certificate cert = javax.security.cert.X509Certificate.getInstance(certBytes);
        return convertX509Cert(cert);
    }
    
    /**
     * Convert a <b>javax</b> X509Certificate to a <b>java</b> X509Certificate.
     *
     * @param cert A certificate in <b>javax.security.cert.X509Certificate</b> format
     * @return A certificate in <b>java.security.cert.X509Certificate</b> format
     */
    public static java.security.cert.X509Certificate convertX509Cert(javax.security.cert.X509Certificate cert)
            throws java.security.cert.CertificateEncodingException,
            javax.security.cert.CertificateEncodingException,
            java.security.cert.CertificateException,
            javax.security.cert.CertificateException {
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        return (java.security.cert.X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
    }
}
