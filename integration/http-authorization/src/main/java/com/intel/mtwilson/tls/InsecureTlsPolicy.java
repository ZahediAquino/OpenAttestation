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

package com.intel.mtwilson.tls;

import com.intel.mtwilson.crypto.NopX509TrustManager;
import com.intel.mtwilson.util.net.InternetAddress;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This trust policy must be initialized with the server that is being checked
 * and its associated server-specific keystore. 
 * 
 * The keystore must already have a trusted certificate for this server. 
 * This policy never adds new certificates to the keystore.
 * 
 * @author jbuhacoff
 */
public class InsecureTlsPolicy implements TlsPolicy, ApacheTlsPolicy {
    private Logger log = LoggerFactory.getLogger(getClass());
//    private final InternetAddress server;
    private final static NopX509TrustManager nop = new NopX509TrustManager();
    private final static ArrayCertificateRepository emptyRepository = new ArrayCertificateRepository(new X509Certificate[0]);
    public InsecureTlsPolicy() { }
    
    public InsecureTlsPolicy(InternetAddress server) {
//        this.server = server;
    }
    
    @Override
    public X509TrustManager getTrustManager() { return nop; }

    @Override
    public HostnameVerifier getHostnameVerifier() {
        return SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
    }

    @Override
    public X509HostnameVerifier getApacheHostnameVerifier() {
        return SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
    }

    @Override
    public CertificateRepository getCertificateRepository() {
        return emptyRepository;
    }
    
}
