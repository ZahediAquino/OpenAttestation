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

package com.intel.mtwilson.agent.intel;

import com.intel.mountwilson.as.helper.TrustAgentSecureClient;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mountwilson.manifest.helper.TAHelper;
import com.intel.mtwilson.agent.HostAgent;
import com.intel.mtwilson.crypto.X509Util;
import com.intel.mtwilson.datatypes.InternetAddress;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Instances of VmwareAgent should be created by the VmwareAgentFactory
 * @author jbuhacoff
 */
public class IntelHostAgent implements HostAgent {
    private transient Logger log = LoggerFactory.getLogger(getClass());
    private transient final TrustAgentSecureClient trustAgentClient;
//    private final String hostname;
    private InternetAddress hostAddress;
    private Boolean isTpmAvailable = null;
    private String vendorHostReport = null;
    private String vmmName = null;
    private HashMap<String, ? extends IManifest> manifestMap = null; // XXX TODO needs to change, it's not a clear programming interface
    
    public IntelHostAgent(TrustAgentSecureClient client, InternetAddress hostAddress) throws Exception {
        trustAgentClient = client;
        this.hostAddress = hostAddress;
//        this.hostname = hostname;
    }
    
    @Override
    public HashMap<String, ? extends IManifest> getManifest() {
        // XXX TODO  obtain the manifest map  using existing code in one of the trust agent helper classes
        return manifestMap;
    }
    
    
    @Override
    public boolean isTpmAvailable() {
//        throw new UnsupportedOperationException("Not supported yet.");
        // bug #538  for now assuming all trust-agent hosts have tpm since we don't have a separate capabilities call
        return true; //  XXX TODO need to have a separate call to trust agent to get host capabilities  ... see bug #540
    }

    @Override
    public boolean isTpmEnabled() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isEkAvailable() {
        return false; // vmware does not make the EK available through its API
    }

    @Override
    public boolean isAikAvailable() { // XXX TODO need to distinguish between "the host system could have an AIK" (maybe isAikSupported) and "the host system actually does have an AIK" (isAikAvailable)
        return true;  // assume we can always get an AIK from a trust agent,  for now
    }

    @Override
    public boolean isAikCaAvailable() { // XXX TODO probably needs to be separated like isAik*  into isAikCaSupported and isAikCaAvailable .    AikCa is synonym for PrivacyCa.
        return true; // assume hosts running trust agent always use a privacy ca,  for now
    }

    @Override
    public boolean isDaaAvailable() {
        return false; // intel trust agent currently does not support DAA
    }

    @Override
    public X509Certificate getAikCertificate() {
        String pem = trustAgentClient.getAIKCertificate();
        try {
            X509Certificate aikCert = X509Util.decodePemCertificate(pem);
            isTpmAvailable = true;
            return aikCert;
        }
        catch(Exception e) {
            log.error("Cannot decode AIK certificate: {}", e.toString());
            log.debug(pem);
            return null;
        }
    }

    @Override
    public String getHostAttestationReport(String pcrList) throws IOException {
        if( vendorHostReport != null ) { return vendorHostReport; }
//        if( vmmName == null ) { getHostDetails(); } // XXX host details API is not part of core so you have to get it another way
        try {
            TAHelper helper = new TAHelper();
            HashMap<String, PcrManifest> pcrMap = helper.getQuoteInformationForHost(hostAddress.toString(), trustAgentClient, pcrList);
            vendorHostReport = helper.getHostAttestationReport(hostAddress.toString(), pcrMap, vmmName);
            log.debug("Host attestation report for {}", hostAddress);
            log.debug(vendorHostReport);
            return vendorHostReport;
        }
        catch(Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public PublicKey getAik() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
