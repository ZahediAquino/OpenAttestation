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
import com.intel.mtwilson.util.net.InternetAddress;
import com.intel.mtwilson.x500.DN;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jbuhacoff
 */
public class ArrayCertificateRepository implements CertificateRepository {
    private Logger log = LoggerFactory.getLogger(getClass());
    private X509Certificate[] keystore;
    private transient Integer hashCode = null;
    
    public ArrayCertificateRepository(X509Certificate[] certificates) {
        keystore = certificates;
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
     * 
     * @param dnsHostnameOrIpAddress
     * @return the first matching certificate in the list
     */
    // XXX not being used;  was part of previous draft interface of CertificateRepository
//    @Override
    public X509Certificate getCertificateForAddress(InternetAddress dnsHostnameOrIpAddress) {
        System.out.println("ArrayCertificateRepository: getCertificateForAddress("+dnsHostnameOrIpAddress.toString()+")");
        for(X509Certificate x509 : keystore) {
            System.out.println("- x509 subject: "+x509.getSubjectX500Principal().getName());
            DN dn = new DN(x509.getSubjectX500Principal().getName());    
            if( dn.getCommonName() != null && dn.getCommonName().equals(dnsHostnameOrIpAddress.toString()) ) {
                System.out.println("- found subject");
                return x509;
            }
            Set<String> alternativeNames = X509Util.alternativeNames(x509);
            for(String alternativeName : alternativeNames) {
                System.out.println("x509 alternative name: "+alternativeName);
                if( alternativeName.equals(dnsHostnameOrIpAddress.toString()) ) {
                System.out.println("- found alternative name");
                    return x509;
                }
            }
        }
        return null;
    }
    
    // XXX not being used;  was part of previous draft interface of CertificateRepository
//    @Override
    public List<X509Certificate> getCertificateForSubject(String subjectDN) {
        ArrayList<X509Certificate> subjectCerts = new ArrayList<X509Certificate>(keystore.length);
        for(X509Certificate x509 : keystore) {
            System.out.println("x509 subject: "+x509.getSubjectX500Principal().getName());
            if( subjectDN.equals(x509.getSubjectX500Principal().getName()) ) {
                subjectCerts.add(x509);
            }
        }
        return subjectCerts;
    }

    // XXX not being used;  was part of previous draft interface of CertificateRepository
//    @Override
    public List<X509Certificate> getCertificateAuthorities() {
        ArrayList<X509Certificate> caCerts = new ArrayList<X509Certificate>(keystore.length);
        for(X509Certificate cert : keystore) {
            if( X509Util.isCA(cert) ) {
                caCerts.add(cert);
            }
        }
        return caCerts;
    }

    @Override
    public List<X509Certificate> getCertificates() {
        ArrayList<X509Certificate> allCerts = new ArrayList<X509Certificate>(keystore.length);
        allCerts.addAll(Arrays.asList(keystore));
        return allCerts;
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
        HashCodeBuilder builder = new HashCodeBuilder(11,31);
        if( keystore != null ) {
            for(int i=0; i<keystore.length; i++) {
                try {
                    builder.append(keystore[i].getEncoded());
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
        ArrayCertificateRepository rhs = (ArrayCertificateRepository)other;
        return new EqualsBuilder().append(hashCode(), rhs.hashCode()).isEquals();
    }    
}
