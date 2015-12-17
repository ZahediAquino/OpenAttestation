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

//import com.intel.mtwilson.crypto.X509Util;
import com.intel.mtwilson.util.x509.X509Util;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jbuhacoff
 */
public class TrustCaAndVerifyHostnameTlsPolicy implements TlsPolicy, ApacheTlsPolicy, X509TrustManager {
    private Logger log = LoggerFactory.getLogger(getClass());
    private CertificateRepository repository;

    public TrustCaAndVerifyHostnameTlsPolicy() { }
    public TrustCaAndVerifyHostnameTlsPolicy(CertificateRepository repository) {
        setKeystore(repository);
    }
    
    public final void setKeystore(CertificateRepository repository) {
        this.repository = repository;
    }
    
    @Override
    public X509TrustManager getTrustManager() { return this;
    /*
        try {
            return SslUtil.createX509TrustManagerWithCertificates(repository.getCertificateAuthorities().toArray(new X509Certificate[0]));  // we either need to make a getCertificateAuthorities():X509Certificate[] function in the CertificateRepository interface, or write our own path-builder using the existing function getCertificateForSubjetByIssuer
        }
        catch(Exception e) {
            System.err.println("Cannot create X509 Trust Manager with Keystore: "+e.toString());
            return new DenyAllTrustManager();
        }*/
    }

    @Override
    public HostnameVerifier getHostnameVerifier() {
        return SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
    }
    
    @Override
    public X509HostnameVerifier getApacheHostnameVerifier() {
        return SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
    }
    
    @Override
    public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
        if( xcs == null || xcs.length == 0 ) { throw new IllegalArgumentException("Server did not present any certificates"); }
        System.out.println("TlsPolicyTrustCaAndVerifyHostname(#"+xcs.length+","+string+")");
//        List<X509Certificate> trustedAuthorities = repository.getCertificateAuthorities();
        List<X509Certificate> trustedCertificates =  repository.getCertificates();
        List<X509Certificate> trustedSubjects = getSubjects(trustedCertificates); //repository.getCertificateForSubject(xcs[i].getSubjectX500Principal().getName());  
        List<X509Certificate> trustedIssuers = getIssuers(trustedCertificates);
        for(int i=0; i<xcs.length; i++) {
//            System.out.println(String.format("xcs[%d] = %s", i, xcs[i].getSubjectX500Principal().getName()));
            // for each certificate in the chain, check if we know it as a trusted cert or if it is signed by one of our trusted certs
            for(X509Certificate trustedCert : trustedSubjects) {
                if( Arrays.equals(trustedCert.getEncoded(), xcs[i].getEncoded())) {
                    try {
                        xcs[i].checkValidity(); // CertificateExpiredException, CertificateNotYetValidEception
                        return;
                    }
                    catch(Exception e) {
                        log.trace("TrustCaAndVerifyHostnameTlsPolicy checkServerTrusted cert did not pass validity. checking next cert");
                        // this certificate is not a copy of xcs[i], but we continue to check other certificates
                    }
                }
            }
            //List<X509Certificate> trustedIssuers = repository.getCertificateForSubject(xcs[i].getIssuerX500Principal().getName());
            for(X509Certificate trustedIssuer : trustedIssuers) {
                System.out.println("- checking against trusted issuer: "+trustedIssuer.getSubjectX500Principal().getName());
                // check if the trusted issuer signed xcs[i]
                try {
                    xcs[i].verify(trustedIssuer.getPublicKey()); // NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, CertificateException
                    xcs[i].checkValidity(); // CertificateExpiredException, CertificateNotYetValidEception
                    return;// XXX TODO   this works because if any of our trusted certs signed it, we're ok -  but we need to make sure there is a valid certificate PATH from xcs[0] to xcs[i] 
                }
                catch(Exception e) {
                    log.trace("TrustCaAndVerifyHostnameTlsPolicy checkServerTrusted cert was not signed. checking next cert");
                    // this issuer did not sign xcs[i], but we continue checking other issuers
                }
            }
        }
        throw new CertificateException("Server certificate is not trusted");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return getIssuers(repository.getCertificates()).toArray(new X509Certificate[0]); //repository.getCertificateAuthorities().toArray(new X509Certificate[0]);
    }
    
    private List<X509Certificate> getSubjects(List<X509Certificate> certificates) {
        ArrayList<X509Certificate> subjectCerts = new ArrayList<X509Certificate>(certificates.size());
        for(X509Certificate cert : certificates) {
            if( !X509Util.isCA(cert) ) {
                subjectCerts.add(cert);
            }
        }
        return subjectCerts;
    }

    private List<X509Certificate> getIssuers(List<X509Certificate> certificates) {
        ArrayList<X509Certificate> caCerts = new ArrayList<X509Certificate>(certificates.size());
        for(X509Certificate cert : certificates) {
            if( X509Util.isCA(cert) ) {
                caCerts.add(cert);
            }
        }
        return caCerts;        
    }

    @Override
    public CertificateRepository getCertificateRepository() {
        return repository;
    }
    
    
}
