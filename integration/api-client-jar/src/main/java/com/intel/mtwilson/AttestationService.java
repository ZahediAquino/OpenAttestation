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

package com.intel.mtwilson;

import com.intel.mtwilson.util.net.Hostname;
import com.intel.mountwilson.as.hostmanifestreport.data.HostManifestReportType;
import com.intel.mountwilson.as.hosttrustreport.data.HostsTrustReportType;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.datatypes.xml.HostTrustXmlResponse;
import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import javax.xml.bind.JAXBException;

/**
 *
 * @author jbuhacoff
 */
public interface AttestationService {
    
    HostLocation getHostLocation(Hostname hostname) throws IOException, ApiException, SignatureException;
    
    boolean addHostLocation(HostLocation hostLocObj) throws IOException, ApiException, SignatureException;

    HostTrustResponse getHostTrust(Hostname hostname) throws IOException, ApiException, SignatureException;

    boolean addHost(TxtHost host) throws IOException, ApiException, SignatureException;

    boolean updateHost(TxtHost host) throws IOException, ApiException, SignatureException;

    boolean deleteHost(Hostname hostname) throws IOException, ApiException, SignatureException;

    List<TxtHostRecord> queryForHosts(String searchCriteria) throws IOException, ApiException, SignatureException;

    OpenStackHostTrustLevelReport pollHosts(List<Hostname> hostnames) throws IOException, ApiException, SignatureException;


    HostsTrustReportType getHostTrustReport (List<Hostname> hostnames) throws IOException, ApiException, SignatureException, JAXBException;

    HostManifestReportType getHostManifestReport (Hostname hostname) throws IOException, ApiException, SignatureException, JAXBException;

    String getHostAttestationReport(Hostname hostname) throws IOException, ApiException, SignatureException;
    
    AttestationReport getAttestationFailureReport(Hostname hostname)throws IOException, ApiException, SignatureException;
    
    
    AttestationReport getAttestationReport(Hostname hostname) throws IOException, ApiException, SignatureException;

    X509Certificate getTlsCertificateForTrustedHost(Hostname hostname) throws IOException, ApiException, SignatureException;
    
    String getSamlForHost(Hostname hostname) throws IOException, ApiException, SignatureException;
    
    String getSamlForHost(Hostname hostname, boolean forceVerify) throws IOException, ApiException, SignatureException;
    
    String getSamlForMultipleHosts(Set<Hostname> hostnames, boolean forceVerify) throws IOException, ApiException, SignatureException;
    
    //List<HostTrustXmlResponse> getSamlForMultipleHosts(Set<Hostname> hostnames, boolean forceVerify) throws IOException, ApiException, SignatureException;
    
}
