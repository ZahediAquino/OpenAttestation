/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/* */
package com.intel.mtwilson.agent.citrix;

import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mountwilson.as.helper.CommandUtil;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mountwilson.manifest.helper.TAHelper;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.tls.TlsConnection;
import com.xensource.xenapi.APIVersion;
import com.xensource.xenapi.Connection;
import com.xensource.xenapi.Host;
import com.xensource.xenapi.Session;
import com.xensource.xenapi.Types.BadServerResponse;
import com.xensource.xenapi.Types.XenAPIException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.configuration.Configuration;
import org.apache.xmlrpc.XmlRpcException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/* */

/**
 *
 * @author stdalex
 */
/*  */
public class CitrixClient {
    private transient Logger log = LoggerFactory.getLogger(getClass());
    
    String hostIpAddress;
    int port;
    String userName;
    String password;
    String connectionString;
    
    private String aikverifyhome;
    private String aikverifyhomeData;
    private String aikverifyhomeBin;
    private String opensslCmd;
    private String aikverifyCmd;
    private TlsConnection tlsConnection;
    private Pattern pcrNumberPattern = Pattern.compile("[0-9]|[0-1][0-9]|2[0-3]"); // integer 0-23 with optional zero-padding (00, 01, ...)
    private Pattern pcrValuePattern = Pattern.compile("[0-9a-fA-F]{40}"); // 40-character hex string
    private String pcrNumberUntaint = "[^0-9]";
    private String pcrValueUntaint = "[^0-9a-fA-F]";
    
    protected Connection connection;
	
     public CitrixClient(TlsConnection tlsConnection){
        this.tlsConnection = tlsConnection;
        this.connectionString = tlsConnection.getConnectionString();
        log.debug("stdalex init cs == " + this.connectionString );
//      log.info("CitrixClient connectionString == " + connectionString);
        // connectionString == citrix:https://xenserver:port;username;password  or citrix:https://xenserver:port;u=username;p=password  or the same w/o the citrix prefix
        String[] parts = this.connectionString.split(";");
        //0 citrix:https://xenserver:port
        //1 username
        //2 password  
         try {
                URL url = new URL(connectionString.replace("citrix:",""));
                hostIpAddress = url.getHost();
                port = url.getPort();
                if( port == -1 ) {
                    port=443;
                }
         }
        catch(MalformedURLException e) {
                throw new IllegalArgumentException("Invalid Citrix XenServer connection string: "+connectionString, e);
        }
        userName = parts[1];
        password = parts[2];
       
        log.info("stdalex-error citrixInit IP:" + hostIpAddress + " port:" + port + " user: " + userName + " pw:" + password);
               
        Configuration config = ASConfig.getConfiguration();
        aikverifyhome = config.getString("com.intel.mountwilson.as.home", "C:/work/aikverifyhome");
        aikverifyhomeData = aikverifyhome+File.separator+"data";
        aikverifyhomeBin = aikverifyhome+File.separator+"bin";
        opensslCmd = aikverifyhomeBin + File.separator + config.getString("com.intel.mountwilson.as.openssl.cmd", "openssl.bat");
        
    }
    
    public void init() {
        boolean foundAllRequiredFiles = true;
        String required[] = new String[] { aikverifyhome, opensslCmd, aikverifyhomeData };
        for(String filename : required) {
            File file = new File(filename);
            if( !file.exists() ) {
                log.info( String.format("Invalid service configuration: Cannot find %s", filename ));
                foundAllRequiredFiles = false;
            }
        }
        if( !foundAllRequiredFiles ) {
            throw new ASException(ErrorCode.AS_CONFIGURATION_ERROR, "Cannot find aikverify files");
        }
        
        // we must be able to write to the data folder in order to save certificates, nones, public keys, etc.
        //log.info("stdalex-error checking to see if we can write to " + aikverifyhomeData);
        File datafolder = new File(aikverifyhomeData);
        if( !datafolder.canWrite() ) {
            throw new ASException(ErrorCode.AS_CONFIGURATION_ERROR, String.format(" Cannot write to %s", aikverifyhomeData));            
        }    
        
    }
	
	
    
    public class keys {
     public String tpmEndCert;
     public String tpmEndKeyPEM;
     public String tpmAttKeyPEM;
     public String tpmAttKeyTCPA;
     
     public keys() {}
    }
    
    public void connect() throws NoSuchAlgorithmException, KeyManagementException, BadServerResponse, XenAPIException, XmlRpcException, XmlRpcException {
            URL url = null; 
            try { 
               url = new URL("https://" + hostIpAddress + ":" + port); 
            }catch (MalformedURLException e) { 
               throw new ASException(e,ErrorCode.AS_HOST_COMMUNICATION_ERROR, hostIpAddress);
            } 
            
            TrustManager[] trustAllCerts = new TrustManager[] { tlsConnection.getTlsPolicy().getTrustManager() };
            
            // Install the all-trusting trust manager  
            SSLContext sc = SSLContext.getInstance("SSL");  
            // Create empty HostnameVerifier  
            HostnameVerifier hv = tlsConnection.getTlsPolicy().getHostnameVerifier();  
 
            sc.init(null, trustAllCerts, new java.security.SecureRandom());  
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());  
            HttpsURLConnection.setDefaultHostnameVerifier(hv); 
			
            connection = new Connection(url);
        
         Session.loginWithPassword(connection, userName, password, APIVersion.latest().toString());
            
    }
	
    public boolean isConnected() { return connection != null; }
    
    public void disconnect() throws BadServerResponse, XenAPIException, XmlRpcException {
        Session.logout(connection);
//        connection.dispose();
    }
    
    public HashMap<String, PcrManifest> getQuoteInformationForHost(String pcrList) {
          log.debug("getQuoteInformationForHost pcrList == " + pcrList);
          try {
            
              // We cannot reuse the connections across different calls since they are tied to a particular host.
              if( !isConnected()) { connect(); } 
              
            String nonce = generateNonce();
            String sessionId = generateSessionId();

			// We do not need to connect again. So, commenting it out.
            // System.err.println("stdalex-error connecting with " + userName + " " + password);
            // Session.loginWithPassword(connection, userName, password, APIVersion.latest().toString());
			
            // System.err.println( "CitrixClient: connected to server ["+hostIpAddress+"]");	
			 
            Map<String, String> myMap = new HashMap<String, String>();
            Set<Host> hostList = Host.getAll(connection);
            Iterator iter = hostList.iterator();
            // hasNext() will always be valid otherwise we will get an exception from the getAll method. So, we not need
            // to throw an exception if the hasNext is false.
            Host h = null;
            if (iter.hasNext()) {
                h = (Host)iter.next();
            } 
			
            String aik = h.callPlugin(connection,  "tpm","tpm_get_attestation_identity", myMap);
           
            int startP = aik.indexOf("<xentxt:TPM_Attestation_KEY_PEM>");
            int endP   = aik.indexOf("</xentxt:TPM_Attestation_KEY_PEM>");
            // 32 is the size of the opening tag  <xentxt:TPM_Attestation_KEY_PEM>
            String cert = aik.substring(startP + "<xentxt:TPM_Attestation_KEY_PEM>".length(),endP);
            log.debug("aikCert == " + cert);
            
            keys key = new keys();
            
            key.tpmAttKeyPEM = cert;  // This is the actual value for AIK!!!!!

			
            String aikCertificate = key.tpmAttKeyPEM;
            
            log.debug( "extracted aik cert from response: " + aikCertificate);
            
            myMap = new HashMap<String, String>();
            myMap.put("nonce",nonce);
            String quote = h.callPlugin(connection, "tpm", "tpm_get_quote", myMap);

            log.debug("extracted quote from response: "+ quote);
            //saveFile(getCertFileName(sessionId), Base64.decodeBase64(aikCertificate));
            saveFile(getCertFileName(sessionId),aikCertificate.getBytes());
            log.debug( "saved certificate with session id: "+sessionId);
            
            saveQuote(quote, sessionId);

            log.debug( "saved quote with session id: "+sessionId);
            
            saveNonce(nonce,sessionId);
            
            log.debug( "saved nonce with session id: "+sessionId);
            
            //createRSAKeyFile(sessionId);

           log.debug( "created RSA key file for session id: "+sessionId);
            
            HashMap<String, PcrManifest> pcrMap = verifyQuoteAndGetPcr(sessionId, pcrList);
            
            log.debug( "Got PCR map");
            //log.log(Level.INFO, "PCR map = "+pcrMap); // need to untaint this first
            
            return pcrMap;
            
        } catch (ASException e) {
            throw e;
//        } catch(UnknownHostException e) {
//            throw new ASException(e,ErrorCode.AS_HOST_COMMUNICATION_ERROR, hostIpAddress);
        }  catch (Exception e) {
            log.debug("caught exception during login: " + e.toString() + " class: " + e.getClass());
            throw new ASException(e, ErrorCode.AS_CITRIX_ERROR, e.toString());
        }
    }
    private HashMap<String,PcrManifest> verifyQuoteAndGetPcr(String sessionId, String pcrList) {
        HashMap<String,PcrManifest> pcrMp = new HashMap<String,PcrManifest>();
        log.info( "verifyQuoteAndGetPcr for session {}",sessionId);
        String certFileName = aikverifyhomeData + File.separator + getCertFileName(sessionId);
        String nonceFileName = aikverifyhomeData + File.separator+getNonceFileName(sessionId);
        String quoteFileName = aikverifyhomeData + File.separator+getQuoteFileName(sessionId);
        List<String> result = TAHelper.aikqverify(nonceFileName, certFileName, quoteFileName); 
        // Sample output from command:
        //  1 3a3f780f11a4b49969fcaa80cd6e3957c33b2275
        //  17 bfc3ffd7940e9281a3ebfdfa4e0412869a3f55d8
        //log.log(Level.INFO, "Result - {0} ", result); // need to untaint this first
        
        //List<String> pcrs = getPcrsList(); // replaced with regular expression that checks 0-23
        List<String> pcrs = Arrays.asList(pcrList.split(","));
        
        for(String pcrString: result){
            String[] parts = pcrString.trim().split(" ");
            if( parts.length == 2 ) {
                String pcrNumber = parts[0].trim().replaceAll(pcrNumberUntaint, "").replaceAll("\n", "");
                String pcrValue = parts[1].trim().replaceAll(pcrValueUntaint, "").replaceAll("\n", "");
                boolean validPcrNumber = pcrNumberPattern.matcher(pcrNumber).matches();
                boolean validPcrValue = pcrValuePattern.matcher(pcrValue).matches();
                if( validPcrNumber && validPcrValue ) {
                	log.info("Result PCR "+pcrNumber+": "+pcrValue);
                    if(pcrs.contains(pcrNumber)) 
                        pcrMp.put(pcrNumber, new PcrManifest(Integer.parseInt(pcrNumber),pcrValue));            	
                }            	
            }
            else {
            	log.warn( "Result PCR invalid");
            }
        }
        
        return pcrMp;
        
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

            log.info( "Nonce Generated " + nonce);
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


            log.info( "Session Id Generated [" + sessionId + "]");

        

        return sessionId;

    }
    
    private String getNonceFileName(String sessionId) {
        return "nonce_" + sessionId +".data";
    }

    private String getQuoteFileName(String sessionId) {
        return "quote_" + sessionId +".data";
    }


    private String getCertFileName(String sessionId) {
        return "aikcert_" + sessionId + ".cer";
    }

    private void saveFile(String fileName, byte[] contents) throws IOException  {
        FileOutputStream fileOutputStream = null;

        try {
            assert aikverifyhome != null;
            log.debug( String.format("saving file %s to [%s]", fileName, aikverifyhomeData));
            fileOutputStream = new FileOutputStream(aikverifyhomeData + File.separator +fileName);
            assert fileOutputStream != null;
            assert contents != null;
            fileOutputStream.write(contents);
            fileOutputStream.flush();
        }
        catch(FileNotFoundException e) {
            log.warn( String.format("cannot save to file %s in [%s]: %s", fileName, aikverifyhomeData, e.getMessage()));
            throw e;
        } finally {
            if (fileOutputStream != null) {
                try {
                    fileOutputStream.close();
                } catch (IOException ex) {
                    log.warn(String.format("Cannot close file %s in [%s]: %s", fileName, aikverifyhomeData, ex.getMessage()));
                }
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
/* */
    // Commenting the below function since it is not being used and klocwork is throwing a warning
    /*private void createRSAKeyFile(String sessionId)  {
        
        String command = String.format("%s %s %s",opensslCmd,aikverifyhomeData + File.separator + getCertFileName(sessionId),aikverifyhomeData + File.separator+getRSAPubkeyFileName(sessionId)); 
        log.debug( "RSA Key Command " + command);
        CommandUtil.runCommand(command, false, "CreateRsaKey" );
        //log.log(Level.INFO, "Result - {0} ", result);
    } */

    /*private String getRSAPubkeyFileName(String sessionId) {
        return "rsapubkey_" + sessionId + ".key";
    }*/ 
    /*
    public HostInfo getHostInfo() throws NoSuchAlgorithmException, KeyManagementException, MalformedURLException, BadServerResponse, XenAPIException,  XmlRpcException  {
        //log.info("stdalex-error getHostInfo IP:" + hostIpAddress + " port:" + port + " user: " + userName + " pw:" + password);
         HostInfo response = new HostInfo();
         
         if( !isConnected()) { connect(); } 
             
       log.debug( "CitrixClient: connected to server ["+hostIpAddress+"]");
			
			 
      // Map<String, String> myMap = new HashMap<String, String>();
       Set<Host> hostList = Host.getAll(connection);
       Iterator iter = hostList.iterator();
        // hasNext() will always be valid otherwise we will get an exception from the getAll method. So, we not need
        // to throw an exception if the hasNext is false.
       Host h = null;
        if (iter.hasNext()) {       
            h = (Host)iter.next();
        }
       
       response.setClientIp(hostIpAddress);

       Map<String, String> map = h.getSoftwareVersion(connection);
       response.setOsName(map.get("product_brand"));
       response.setOsVersion(map.get("product_version"));
       response.setVmmName("xen");
       response.setVmmVersion(map.get("xen"));
       
       map = h.getBiosStrings(connection);
       response.setBiosOem(map.get("bios-vendor"));
       response.setBiosVersion(map.get("bios-version"));
       
       map = h.getCpuInfo(connection);
       int stepping = Integer.parseInt(map.get("stepping"));
       int model = Integer.parseInt(map.get("model"));
       int family = Integer.parseInt(map.get("family"));
       // EAX register contents is used for defining CPU ID and as well as family/model/stepping
       // 0-3 bits : Stepping
       // 4-7 bits: Model #
       // 8-11 bits: Family code
       // 12 & 13: Processor type, which will always be zero
       // 14 & 15: Reserved
       // 16 to 19: Extended model
       // Below is the sample of the data got from the Citrix API
       // Model: 45, Stepping:7 and Family: 6
       // Mapping it to the EAX register we would get
       // 0-3 bits: 7
       // 4-7 bits: D (Actually 45 would be 2D. So, we would put D in 4-7 bits and 2 in 16-19 bits
       // 8-11 bits: 6
       //12-15 bits: 0
       // 16-19 bits: 2
       // 20-31 bits: Extended family and reserved, which will be 0
       // So, the final content would be : 000206D7
       // On reversing individual bytes, we would get D7 06 02 00
       String modelInfo = Integer.toHexString(model);
       String processorInfo = modelInfo.charAt(1) + Integer.toHexString(stepping) + " " + "0" + Integer.toHexString(family) + " " + "0" + modelInfo.charAt(0);
       processorInfo = processorInfo.trim().toUpperCase();
       response.setProcessorInfo(processorInfo);
       java.util.Date date= new java.util.Date();
       response.setTimeStamp( new Timestamp(date.getTime()).toString());
//       log.trace("stdalex-error leaving getHostInfo");
              
       return response;
    }
    */
/* */ 
    public String getAIKCertificate() throws NoSuchAlgorithmException, KeyManagementException, BadServerResponse, XenAPIException,  XmlRpcException {
        String resp = "";
        log.info("stdalex-error getAIKCert IP:" + hostIpAddress + " port:" + port + " user: " + userName + " pw:" + password); // removed to prevent leaking secrets
               
        if( !isConnected()) { connect(); } 

       log.debug( "CitrixClient: connected to server ["+hostIpAddress+"]");
			
			 
       Map<String, String> myMap = new HashMap<String, String>();
       Set<Host> hostList = Host.getAll(connection);
       Iterator iter = hostList.iterator();
        // hasNext() will always be valid otherwise we will get an exception from the getAll method. So, we not need
        // to throw an exception if the hasNext is false.
       Host h = null;
        if (iter.hasNext()) {       
          h = (Host)iter.next();
        }
        
       String aik = h.callPlugin(connection,  "tpm","tpm_get_attestation_identity", myMap);
       
       int startP = aik.indexOf("<xentxt:TPM_Attestation_KEY_PEM>");
       int endP   = aik.indexOf("</xentxt:TPM_Attestation_KEY_PEM>");
       // 32 is the size of the opening tag  <xentxt:TPM_Attestation_KEY_PEM>
       String cert = aik.substring(startP + "<xentxt:TPM_Attestation_KEY_PEM>".length(),endP);
       log.debug("aikCert == " + cert);
      
            
       keys key = new keys();
           
       key.tpmAttKeyPEM = cert;  // This is the actual value for AIK!!!!!

       
       //resp = new String( Base64.decodeBase64(key.tpmAttKeyPEM));
       resp = key.tpmAttKeyPEM;//new String(key.tpmAttKeyPEM);
       
//       log.trace("stdalex-error getAIKCert: returning back: " + resp);
       return resp;
    }
}
/* */
