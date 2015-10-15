//CitrixHostAgent
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/* */
package com.intel.mtwilson.agent.citrix;


import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;

import com.intel.mtwilson.agent.HostAgent;
import com.intel.mtwilson.crypto.CryptographyException;
import com.intel.mtwilson.crypto.X509Util;
import com.intel.mtwilson.datatypes.TxtHostRecord;
import com.xensource.xenapi.Types.BadServerResponse;
import com.xensource.xenapi.Types.XenAPIException;
import java.io.IOException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import org.apache.commons.codec.binary.Base64;
import org.apache.xmlrpc.XmlRpcException;
/* */

/**
 *
 * @author stdalex
 */
/* */
public class CitrixHostAgent implements HostAgent{
    private CitrixClient client;
    private Logger log = LoggerFactory.getLogger(getClass());
    private HashMap<String, ? extends IManifest> manifestMap = null; // XXX TODO needs to change, it's not a clear programming interface
    public CitrixHostAgent(CitrixClient client) {
     this.client = client;
    }
    
    @Override
    public boolean isTpmAvailable() {
        return true;
    }

    @Override
    public boolean isTpmEnabled() {
        return true;
    }

    @Override
    public boolean isEkAvailable() {
        return true;
    }

    @Override
    public boolean isAikAvailable() {
        return false;
    }

    @Override
    public boolean isAikCaAvailable() {
        return false;
    }

    @Override
    public boolean isDaaAvailable() {
        return true;
    }

    @Override
    public PublicKey getAik() {
        PublicKey pk = null;
         try {
            String crt  = client.getAIKCertificate();
            log.debug(" crt == " + crt);
            pk = X509Util.decodePemPublicKey(crt);
            //client.getAIKCertificate().replace(X509Util.BEGIN_PUBLIC_KEY, "").replace(X509Util.END_PUBLIC_KEY, "").replaceAll("\n","").replaceAll("\r","");  
        }  catch(Exception ex){
            log.debug("getAik caught: " + ex.getMessage()); 
            
        }  
        return pk;
    }
    
    @Override
    public X509Certificate getAikCertificate() {
        throw new UnsupportedOperationException("Not supported!");
    }
    

    public String getHostAttestationReport(String pcrList) throws IOException {
       String attestationReport = "";
        XMLOutputFactory xof = XMLOutputFactory.newInstance();
        XMLStreamWriter xtw;
        StringWriter sw = new StringWriter();
        try {
            xtw = xof.createXMLStreamWriter(sw);
        
            xtw.writeStartDocument();
            xtw.writeStartElement("Host_Attestation_Report");
            xtw.writeAttribute("Host_Name",this.client.hostIpAddress);
            xtw.writeAttribute("vCenterVersion", "5.0");
            xtw.writeAttribute("HostVersion", "5.0");
            //xtw.writeAttribute("TXT_Support", tpmSupport.toString());
        
            HashMap<String, PcrManifest> pcrMap = client.getQuoteInformationForHost(pcrList);
            
            Iterator it = pcrMap.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry pairs = (Map.Entry)it.next();
                xtw.writeStartElement("PCRInfo");
                PcrManifest pcr = (PcrManifest)pairs.getValue();
                xtw.writeAttribute("ComponentName",Integer.toString(pcr.getPcrNumber()));
                xtw.writeAttribute("DigestValue", pcr.getPcrValue());
                xtw.writeEndElement();
               
                it.remove(); // avoids a ConcurrentModificationException
            }
            xtw.writeEndElement();
            xtw.writeEndDocument();
            xtw.flush();
            xtw.close(); 
            attestationReport = sw.toString();
        
        } catch (XMLStreamException ex) {
//            Logger.getLogger(CitrixHostAgent.class.getName()).log(Level.SEVERE, null, ex);
            log.error("Cannot get host attestation report", ex);
        }
        
        log.debug("getHostAttestationReport report:" + attestationReport);
        return attestationReport;
    }

    @Override
    public Map<String, String> getHostAttributes() throws IOException {
       HashMap<String,String> hm = new HashMap<String, String>();
        // Retrieve the data from the host and add it into the hashmap
      // trustAgentClient.getHostAttributes();
       
//        HostInfo hostInfo = client.getHostInfo();
//        // Currently we are just adding the UUID of th host. Going ahead we can add additional details
//        if (hostInfo != null)
//            hm.put("Host_UUID", hostInfo.getHardwareUuid().trim());
        
        return hm;
    }
    @Override
    public HashMap<String, ? extends IManifest> getManifest() {
       return manifestMap;
    }
  
       
}
/* */
