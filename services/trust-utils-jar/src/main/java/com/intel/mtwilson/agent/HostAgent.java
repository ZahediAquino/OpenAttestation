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

package com.intel.mtwilson.agent;

import com.intel.mountwilson.manifest.data.IManifest;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * XXX TODO this is a draft of the interface that Linux, Citrix, and Vmware
 * agents should implement for communicating information about their hosts
 * to Mt Wilson. THis will allow Mt Wilson to treat them uniformly and move
 * all the platform-specific calls and procedures into those agents in a 
 * clean way. 
 * 
 * To obtain a HostAgent object, use the HostAgentFactory to create one for a 
 * given host. All the methods in this interface apply to the given host.
 * 
 * All the methods in this interface are intended to retrieve information
 * from the host (or its master/manager server). 
 * 
 * Note that the HostAgent is not responsible for interpreting the attestation.
 * It is only responsible for obtaining the host information, AIK, TPM Quote,
 * and Module Manifest. The Attestation Service will interpret these.
 * 
 * @author jbuhacoff
 */
public interface HostAgent {
    
    /**
     * Available means the TPM hardware is present.
     * Linux, Citrix, and Vmware agents should contact the host and find out
     * if it has a TPM before determining the return value.
     * @return true if the host has a TPM
     */
    boolean isTpmAvailable();
    
    /**
     * Linux, Citrix agents should contact the host and find out
     * if its TPM is enabled (BIOS enabled and also if the agents have ownership).
     * In this case, "enabled" means it has an owner set AND that owner is
     * cooperating with Mt Wilson. 
     * Vmware agents can return true if isTpmAvailable() returns true.
     * @return 
     */
    boolean isTpmEnabled();
    
    /**
     * Linux and Citrix agents should return true, Vmware should return false.
     * @return true if we can obtain the EK for the host
     */
    boolean isEkAvailable();
    
    /**
     * Linux and Citrix agents should return true, Vmware should return false.
     * @return true if we can obtain am AIK for the host.
     */
    boolean isAikAvailable();
    
    /**
     * Linux agent should return true because we use the Privacy CA.
     * Citrix agent uses DAA so it should return false.
     * Vmware agent should return false.
     * @return 
     */
    
    /**
     * AIK's are RSA public keys.  The certificates only exist when a Privacy CA or
     * a Mt Wilson CA signs the public key to create a certificate.
     * @return 
     */
    PublicKey getAik();
    
    boolean isAikCaAvailable();
    
    /**
     * Linux and Vmware agent should return false.
     * Citrix agent should return true.
     * @return true if the host supports Direct Anonymous Attestation
     */
    boolean isDaaAvailable();
    
    /**
     * XXX draft - maybe it should return an X509Certificate object
     * @return 
     */
    X509Certificate getAikCertificate();
    


    /**
     * Another adapter for existing code.  Each vendor returns a string in their own format.
     * @param pcrList
     * @return
     * @throws IOException 
     */
    String getHostAttestationReport(String pcrList) throws IOException;
    
    
    
    /**
     * Use this to obtain host-specific information such as UUID, which may be 
     * needed for dynamic whitelist rules.  Attributes returned with this method
     * may be referenced by name from dynamic whitelist rules.
     * @return
     * @throws IOException 
     * 
     *  * Format should look something like this
     * <?xml version='1.0' encoding='UTF-8'?>
     * <Host_Attestation_Report Host_Name="10.1.70.126" vCenterVersion="5.0" HostVersion="5.0">
     *      <PCRInfo ComponentName="0" DigestValue="1d670f2ae1dde52109b33a1f14c03e079ade7fea"/>
     *      <PCRInfo ComponentName="17" DigestValue="ca21b877fa54dff86ed5170bf4dd6536cfe47e4d"/>
     *      <PCRInfo ComponentName="18" DigestValue="8cbd66606433c8b860de392efb30d76990a3b1ed"/>
     * </Host_Attestation_Report>
     */
    Map<String,String> getHostAttributes() throws IOException;
    
    
    HashMap<String, ? extends IManifest> getManifest();
}
