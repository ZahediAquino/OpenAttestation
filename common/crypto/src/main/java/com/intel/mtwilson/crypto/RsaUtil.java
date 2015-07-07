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

package com.intel.mtwilson.crypto;

import com.intel.mtwilson.util.io.pem.Pem;
import com.intel.mtwilson.util.io.pem.PemLikeParser;
import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.x509.*;

/**
 * You can also use Java's "keytool" command on your platform to generate keys
 * and add them to a keystore file. Set the "mtwilson.api.keystore" property to
 * point to this file (by default keystore.jks)
 *
 * @since 0.5.2
 * @author jbuhacoff
 */
public class RsaUtil {

    private static Logger log = LoggerFactory.getLogger(RsaUtil.class);
    public static final int MINIMUM_RSA_KEY_SIZE = 2048; // minimum 2048 bits required by Intel SAFE Guidelines
    public static final int DEFAULT_RSA_KEY_EXPIRES_DAYS = 3650; // default 10 years validity for generated keys

    public static KeyPair generateRsaKeyPair(int keySizeInBits) throws NoSuchAlgorithmException {
        KeyPairGenerator r = KeyPairGenerator.getInstance("RSA");
        r.initialize(keySizeInBits);
        KeyPair keypair = r.generateKeyPair();
        return keypair;
    }

    /**
     * Create a self-signed X.509 Certificate using SHA-256 with RSA encryption.
     * Original source:
     * http://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate.html
     * StackOverflow Question:
     * http://stackoverflow.com/questions/1615871/creating-an-x509-certificate-in-java-without-bouncycastle
     * Java Keytool Source Code (doSelfCert):
     * http://www.docjar.com/html/api/sun/security/tools/KeyTool.java.html
     *
     * XXX This method uses Sun "internal" API's, which may be removed in a
     * future JRE release.
     *
     * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     * @param pair the KeyPair
     * @param days how many days from now the Certificate is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     */
    public static X509Certificate generateX509Certificate(String dn, KeyPair pair, int days) throws CryptographyException, IOException {
        return generateX509Certificate(dn, null, pair, days);
    }

    /**
     * Creates a self-signed X.509 certificate using SHA-256 with RSA
     * encryption.
     *
     * XXX This method uses Sun "internal" API's, which may be removed in a
     * future JRE release.
     *
     * @param dn
     * @param alternativeName a string like "ip:1.2.3.4"
     * @param pair
     * @param days
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static X509Certificate generateX509Certificate(String dn, String alternativeName, KeyPair pair, int days) throws CryptographyException, IOException {
        X500Name owner = new X500Name(dn, "Mt Wilson", "Trusted Data Center", "US"); // the constructor X500Name(dn) was throwing an exception;  replaced "Intel" with "Trusted Data Center" to avoid confusion about the owner of the certificate... this is not an "Intel certificate", it's generated at the customer site.
        return createX509CertificateWithIssuer(pair.getPublic(), dn, alternativeName, days, pair.getPrivate(), new CertificateIssuerName(owner));
    }

    /**
     * Creates an X.509 certificate on the given subject's public key and
     * distinguished name, using the given issuer private key and certificate
     * (used as the source of issuer's name on the newly created certificate).
     *
     * @param subjectPublicKey
     * @param dn
     * @param alternativeName a string like "ip:1.2.3.4"
     * @param days
     * @param issuerPrivateKey
     * @param issuerCertificate
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static X509Certificate createX509CertificateWithIssuer(PublicKey subjectPublicKey, String dn, String alternativeName, int days, PrivateKey issuerPrivateKey, X509Certificate issuerCertificate) throws CryptographyException, IOException {
        X500Name issuerName = X500Name.asX500Name(issuerCertificate.getSubjectX500Principal());
        return createX509CertificateWithIssuer(subjectPublicKey, dn, alternativeName, days, issuerPrivateKey, new CertificateIssuerName(issuerName));
    }

    /**
     * Creates an X.509 certificate on the given subject's public key and
     * distinguished name, using the given issuer private key and issuer name
     * (used as the source of issuer's name on the newly created certificate).
     *
     * @param subjectPublicKey
     * @param dn actually this is just the Common Name portion of the
     * Distinguished Name; the OU, O, and C are added automatically. XXX: this
     * may change in a future version.
     * @param alternativeName a string like "ip:1.2.3.4" or "dns:server.com"
     * @param days the certificate will be valid
     * @param issuerPrivateKey
     * @param issuerName
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static X509Certificate createX509CertificateWithIssuer(PublicKey subjectPublicKey, String dn, String alternativeName, int days, PrivateKey issuerPrivateKey, CertificateIssuerName issuerName) throws IOException, CryptographyException {
//        X509
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name subjectName = new X500Name(dn, "Mt Wilson", "Trusted Data Center", "US"); // the constructor X500Name(dn) was throwing an exception;  replaced "Intel" with "Trusted Data Center" to avoid confusion about the owner of the certificate... this is not an "Intel certificate", it's generated at the customer site.
        AlgorithmId algorithm = null;
        try {
            info.set(X509CertInfo.VALIDITY, interval); // CertificateException, IOException
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn)); // CertificateException, IOException
            info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subjectName)); // CertificateException, IOException
            info.set(X509CertInfo.ISSUER, issuerName); // CertificateException, IOException
            info.set(X509CertInfo.KEY, new CertificateX509Key(subjectPublicKey)); // CertificateException, IOException
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3)); // CertificateException, IOException
            if (alternativeName != null) {
                if(alternativeName.startsWith("ip:")) {
                    //                InetAddress ipAddress = new InetAddress.getByName(alternativeName.substring(3));
                    //                IPAddressName ipAddressName = new IPAddressName(ipAddress.getAddress());
                    IPAddressName ipAddressName = new IPAddressName(alternativeName.substring(3));
                    GeneralNames generalNames = new GeneralNames();
                    generalNames.add(new GeneralName(ipAddressName));
                    SubjectAlternativeNameExtension san = new SubjectAlternativeNameExtension(generalNames);
                    CertificateExtensions ext = new CertificateExtensions();
                    ext.set(san.getExtensionId().toString(), san);
                    info.set(X509CertInfo.EXTENSIONS, ext);
                    //   ObjectIdentifier("2.5.29.17") , false, "ipaddress".getBytes()                            
                }
                if(alternativeName.startsWith("dns:")) {
                    DNSName dnsName = new DNSName(alternativeName.substring(4));
                    GeneralNames generalNames = new GeneralNames();
                    generalNames.add(new GeneralName(dnsName));
                    SubjectAlternativeNameExtension san = new SubjectAlternativeNameExtension(generalNames);
                    CertificateExtensions ext = new CertificateExtensions();
                    ext.set(san.getExtensionId().toString(), san);
                    info.set(X509CertInfo.EXTENSIONS, ext);
                }
            }
            algorithm = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid); // md5WithRSAEncryption_oid
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithm));
        } catch (CertificateException e) {
            throw new CryptographyException("Cannot generate certificate", e);
        }
        try {
            // Sign the cert to identify the algorithm that's used.
            X509CertImpl cert = new X509CertImpl(info);
            System.out.println("Algorithm name: " + algorithm.getName()); // if this isn't SHA256withRSA need to hard code it
            cert.sign(issuerPrivateKey, algorithm.getName()); // NoSuchAlgorithMException, InvalidKeyException, NoSuchProviderException, , SignatureException

            // Update the algorith, and resign.
            algorithm = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
            info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algorithm);
            cert = new X509CertImpl(info);
            cert.sign(issuerPrivateKey, algorithm.getName()); // NoSuchAlgorithMException, InvalidKeyException, NoSuchProviderException, SignatureException
            return cert;
        } catch (CertificateException e) {
            throw new CryptographyException("Cannot sign certificate", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptographyException("Cannot sign certificate", e);
        } catch (InvalidKeyException e) {
            throw new CryptographyException("Cannot sign certificate", e);
        } catch (NoSuchProviderException e) {
            throw new CryptographyException("Cannot sign certificate", e);
        } catch (SignatureException e) {
            throw new CryptographyException("Cannot sign certificate", e);
        }
    }
    
    /**
     * XXX TODO maybe this method should always require a password to use for encrypting the private key.
     * 
     * XXX TODO create other helper methods for p12 format, or creating a java keystore file for just one private key, etc. 
     * 
     * @param privateKey
     * @return 
     * @since 0.1.3
     */
    public static String encodePemPrivateKey(PrivateKey privateKey)  {
        Pem pem = new Pem("PRIVATE KEY", privateKey.getEncoded());
        return pem.toString();
    }
    
    /**
     * Given some text, this method extracts the first PRIVATE KEY block (PEM-like format) and deserializes the 
     * private key, returning a PrivateKey object.
     * This means you can have one file containing both PRIVATE KEY and PUBLIC KEY blocks and extract each
     * key using the corresponding decode method.
     * 
     * XXX TODO maybe this method should allow providing a password for decrypting a password-encrypted private key
     * @param text
     * @return
     * @throws CryptographyException 
     * @since 0.1.3
     */
    public static PrivateKey decodePemPrivateKey(String text) throws CryptographyException {
        List<Pem> list = PemLikeParser.parse(text);
        for(Pem pem : list) {
            if( "PRIVATE KEY".equals(pem.getBanner()) ) {
                byte[] der = pem.getContent();
                return decodeDerPrivateKey(der);
            }
        }
        return null;
//        Pem pem = Pem.valueOf(text);
//        return decodeDerPrivateKey(pem.getContent());
    }
    
    public static PrivateKey decodeDerPrivateKey(byte[] privateKeyBytes) throws CryptographyException {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA"); // throws NoSuchAlgorithmException
            PrivateKey privateKey  = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes)); // throws InvalidKeySpecException
            return privateKey;
        }
        catch(Exception e) {
            throw new CryptographyException(e);
        }
    }
}
