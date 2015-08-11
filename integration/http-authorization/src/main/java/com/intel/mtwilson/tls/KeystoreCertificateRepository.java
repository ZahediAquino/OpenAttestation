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

import com.intel.mtwilson.util.crypto.SimpleKeystore;
//import com.intel.mtwilson.crypto.X509Util;
import com.intel.mtwilson.util.x509.X509Util;
import com.intel.mtwilson.util.net.InternetAddress;
import com.intel.mtwilson.x500.DN;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * XXX TODO instead of (or in addition to) a SimpleKeystore constructor this class
 * should also have a constructor that accepts a JDK KeyStore object.
 * @author jbuhacoff
 */
public class KeystoreCertificateRepository implements MutableCertificateRepository {
    private Logger log = LoggerFactory.getLogger(getClass());
    private SimpleKeystore keystore;
    private transient Integer hashCode = null;
    
    public KeystoreCertificateRepository(SimpleKeystore simpleKeystore) {
        keystore = simpleKeystore;
    }
    
    /**
     * XXX TODO this is a draft; maybe it should return a list , since it's possible
     * for more than one certificate to match...
     * XXX TODO maybe create another method getCurrentCertificateForAddress which refines
     * the search by returning only certificates that are valid NOW (the keystore may
     * have some that are not yet valid because they have been deployed in preparation
     * for an upcoming expiration)
     * 
     * The following certificate attributes are checked in order:
     * Common name in the subject
     * Alternative name
     * Alias in the keystore
     * 
     * @param dnsHostnameOrIpAddress
     * @return the first matching certificate in the keystore; if there is more than one it is not guaranteed to always return the same one because this depends on the keystore implementation
     */
    // XXX not being used;  was part of previous draft interface of CertificateRepository
//    @Override
    public X509Certificate getCertificateForAddress(InternetAddress dnsHostnameOrIpAddress) {
        try {
            String[] sslCertAliases = keystore.listTrustedSslCertificates();
            for(String alias : sslCertAliases) {
                try {
                    X509Certificate x509 = keystore.getX509Certificate(alias);
                    System.out.println("x509 subject: "+x509.getSubjectX500Principal().getName());
                    DN dn = new DN(x509.getSubjectX500Principal().getName());    
                    if( dn.getCommonName() != null && dn.getCommonName().equals(dnsHostnameOrIpAddress.toString()) ) {
                        return x509;
                    }
                    Set<String> alternativeNames = X509Util.alternativeNames(x509);
                    for(String alternativeName : alternativeNames) {
                        System.out.println("x509 alternative name: "+alternativeName);
                        if( alternativeName.equals(dnsHostnameOrIpAddress.toString()) ) {
                            return x509;
                        }
                    }
                    if( alias.equals(dnsHostnameOrIpAddress.toString()+" (ssl)") ) { // XXX TODO need to use the new Tag interface for the simple keystore
                        return x509;
                    }
                }
                catch(Exception e) {
                    log.error("Cannot load certificate alias '"+alias+"' from keystore", e);                    
                }
            }
            return null;
        }
        catch(KeyStoreException e) {
            log.error("Cannot find certificate in keystore", e);
            return null;
        }
    }
    
    @Override
    public void addCertificate(X509Certificate certificate) throws KeyManagementException {
        keystore.addTrustedSslCertificate(certificate, certificate.getSubjectX500Principal().getName());
        try {
            log.debug("Saving keystore");
            keystore.save();
        }
        catch(KeyStoreException e) {
            throw new KeyManagementException("Cannot add certificate to keystore: "+e.toString(), e);
        }
        catch(IOException e) {
            throw new KeyManagementException("Cannot add certificate to keystore: "+e.toString(), e);
        }
        catch(NoSuchAlgorithmException e) {
            throw new KeyManagementException("Cannot add certificate to keystore: "+e.toString(), e);
        }
        catch(CertificateException e) {
            throw new KeyManagementException("Cannot add certificate to keystore: "+e.toString(), e);
        }
        hashCode = null; // signal to recalculate the hashcode due to changed contents
    }
/*
    public void setCertificateForAddress(InternetAddress dnsHostnameOrIpAddress, X509Certificate certificate) throws KeyManagementException {
        keystore.addTrustedSslCertificate(certificate, dnsHostnameOrIpAddress.toString());
    }
    */
    
    // XXX not being used;  was part of previous draft interface of CertificateRepository
//    @Override
    public List<X509Certificate> getCertificateForSubject(String subjectDN) {
        ArrayList<X509Certificate> subjectCerts = new ArrayList<X509Certificate>();
        try {
            String[] sslCertAliases = keystore.listTrustedSslCertificates();
            for(String alias : sslCertAliases) {
                try {
                    X509Certificate x509 = keystore.getX509Certificate(alias);
                    System.out.println("x509 subject: "+x509.getSubjectX500Principal().getName());
                    System.out.println("x509 issuer: "+x509.getIssuerX500Principal().getName());
                    if( subjectDN.equals(x509.getSubjectX500Principal().getName()) ) {
                        subjectCerts.add(x509);
                    }
                }
                catch(Exception e) {
                    log.error("Cannot load certificate alias '"+alias+"' from keystore", e);                    
                }
            }
            return subjectCerts;
        }
        catch(KeyStoreException e) {
            log.error("Cannot find certificate in keystore", e);
            return subjectCerts;
        }
    }

    // XXX not being used;  was part of previous draft interface of CertificateRepository
//    @Override
    public List<X509Certificate> getCertificateAuthorities() {
        ArrayList<X509Certificate> caCerts = new ArrayList<X509Certificate>();
        try {
            String[] caAliases = keystore.listTrustedCaCertificates();
            for(int i=0; i<caAliases.length; i++) {
                caCerts.add(keystore.getX509Certificate(caAliases[i]));
            }
            return caCerts;
        }
        catch(Exception e) {
            log.error("Cannot load certificate authorities from repository", e);
            return caCerts;
        }
    }

    @Override
    public List<X509Certificate> getCertificates() {
        ArrayList<X509Certificate> allCerts = new ArrayList<X509Certificate>();
        try {
            String[] aliases = keystore.aliases();
            for(int i=0; i<aliases.length; i++) {
                allCerts.add(keystore.getX509Certificate(aliases[i]));
            }
            return allCerts;
        }
        catch(Exception e) {
            log.error("Cannot load certificates from repository", e);
            return allCerts;
        }
    }
    
    
    /**
     * Calculates the hash code based on the order and contents of the 
     * certificates in the repository. Two Array Certficate Repository objects
     * are considered equal if they have the same certificates in the same
     * order. 
     * We might relax the order requirement in the future.
     * The hash code is only calculated once, after that it is cached and
     * reused. This assumes the repository will not be modified outside
     * of this object, and since it's presented as a read-only repository that is not likely
     * to happen.
     * @return 
     */
    @Override
    public int hashCode() {
        if( hashCode != null ) { return hashCode; } // use cached value when possible
        HashCodeBuilder builder = new HashCodeBuilder(11,37);
        if( keystore != null ) {
            List<X509Certificate> certificates = getCertificates();
            Collections.sort(certificates, new X509CertificateComparator());
            for(X509Certificate certificate : certificates) {
                try {
                    builder.append(certificate.getEncoded());
                }
                catch(Exception e) {
                    builder.append(e.toString());
                }
            }
        }
        hashCode = builder.toHashCode();
        return hashCode;
    }
    
    @Override
    public boolean equals(Object other) {
        if( other == null ) { return false; }
        if( other == this ) { return true; }
        if( other.getClass() != this.getClass() ) { return false; }
        KeystoreCertificateRepository rhs = (KeystoreCertificateRepository)other;
        return new EqualsBuilder().append(hashCode(), rhs.hashCode()).isEquals();
    }        
}
