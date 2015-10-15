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
import com.intel.mtwilson.util.crypto.SimpleKeystore;
import com.intel.mtwilson.tls.ApacheTlsPolicy;
import com.intel.mtwilson.tls.KeystoreCertificateRepository;
import com.intel.mtwilson.tls.InsecureTlsPolicy;
import com.intel.mtwilson.tls.TrustCaAndVerifyHostnameTlsPolicy;
import com.intel.mtwilson.tls.TrustFirstCertificateTlsPolicy;
import com.intel.mtwilson.tls.TrustKnownCertificateTlsPolicy;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MediaType;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.SystemConfiguration;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @since 0.5.2
 * @author jbuhacoff
 */
public class ApacheHttpClient implements java.io.Closeable {
    private final Logger log = LoggerFactory.getLogger(getClass());    
//    private SchemeRegistry sr;
    private ClientConnectionManager connectionManager;
    private HttpClient httpClient;
//    private SimpleKeystore keystore;
    private String protocol = "https";
    private int port = 443;
//    private boolean requireTrustedCertificate = true;
//    private boolean verifyHostname = true;
    
    protected static final ObjectMapper mapper = new ObjectMapper();
    
    /**
     * If you don't have a specific configuration, you can pass in SystemConfiguration() so that users can set
     * system properties and have them passed through to this object.
     * 
     * TODO: in addition to passing in a keystore object, we should support the standard java properties for the keystore location and password:
                String truststore = System.getProperty("javax.net.ssl.trustStore");
                String truststorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
     * 
     * @param baseURL for the server to access (all requests are based on this URL)
     * @param credentials to use when signing HTTP requests, or null if you want to skip the Authorization header
     * @param sslKeystore containing trusted SSL certificates
     * @param config with parameters requireTrustedCertificates and verifyHostname; if null a SystemConfiguration will be used.
     * @throws NoSuchAlgorithmException
     * @throws KeyManagementException 
     */
    public ApacheHttpClient(URL baseURL, SimpleKeystore sslKeystore, Configuration config) throws NoSuchAlgorithmException, KeyManagementException {
        
        protocol = baseURL.getProtocol();
        port = baseURL.getPort();
        if( port == -1 ) {
            port = baseURL.getDefaultPort();
        }

        if( config == null ) {
            config = new SystemConfiguration();
        }
//        requireTrustedCertificate = config.getBoolean("mtwilson.api.ssl.requireTrustedCertificate", true);
//        verifyHostname = config.getBoolean("mtwilson.api.ssl.verifyHostname", true);
        ApacheTlsPolicy tlsPolicy = createTlsPolicy(config, sslKeystore);
        log.info("Created TlsPolicy: "+tlsPolicy.getClass().getName());
        SchemeRegistry sr = initSchemeRegistryWithPolicy(protocol, port, tlsPolicy);
        connectionManager = new PoolingClientConnectionManager(sr);

        // the http client is re-used for all the requests
        HttpParams httpParams = new BasicHttpParams();
        httpParams.setParameter(ClientPNames.HANDLE_REDIRECTS, false);
        httpClient = new DefaultHttpClient(connectionManager, httpParams);
    }
    
    /**
     * Used in Mt Wilson 1.1
     * 
     * If the configuration mentions a specific TLS Policy (new in 1.1) that
     * one is used, otherwise the trusted certificate and verify hostname 
     * settings used in 1.0-RC2 are used to choose an appropriate TLS Policy.
     * 
     * XXX should this go into a TlsPolicyFactory class in the http-authorization project?
     * 
     * @param config
     * @param sslKeystore
     * @return 
     */
    private ApacheTlsPolicy createTlsPolicy(Configuration config, SimpleKeystore sslKeystore) {
        String tlsPolicyName = config.getString("mtwilson.api.ssl.policy");
        if( tlsPolicyName == null ) {
            // no 1.1 policy name, so use 1.0-RC2 settings to pick a policy
            boolean requireTrustedCertificate = config.getBoolean("mtwilson.api.ssl.requireTrustedCertificate", true);
            boolean verifyHostname = config.getBoolean("mtwilson.api.ssl.verifyHostname", true);
            if( requireTrustedCertificate && verifyHostname ) {
                log.warn("Using TLS Policy TRUST_CA_VERIFY_HOSTNAME");
                return new TrustCaAndVerifyHostnameTlsPolicy(new KeystoreCertificateRepository(sslKeystore));
            }
            else if( requireTrustedCertificate && !verifyHostname ) {
                // two choices: trust first certificate or trust known certificate;  we choose trust first certificate as a usability default
                // furthermore we assume that the api client keystore is a server-specific keystore (it's a client configured for a specific mt wilson server)
                // that either has a server instance ssl cert or a cluster ssl cert.  either should work.
                log.warn("Using TLS Policy TRUST_FIRST_CERTIFICATE");
                return new TrustFirstCertificateTlsPolicy(new KeystoreCertificateRepository(sslKeystore));
            }
            else { // !requireTrustedCertificate && (verifyHostname || !verifyHostname)
                log.warn("Using TLS Policy TRUST_FIRST_INSECURE");
                return new InsecureTlsPolicy();
            }
        }
        else if( tlsPolicyName.equals("TRUST_CA_VERIFY_HOSTNAME") ) {
            log.info("TLS Policy: TRUST_CA_VERIFY_HOSTNAME");
            return new TrustCaAndVerifyHostnameTlsPolicy(new KeystoreCertificateRepository(sslKeystore));
        }
        else if( tlsPolicyName.equals("TRUST_FIRST_CERTIFICATE") ) {
            log.info("TLS Policy: TRUST_FIRST_CERTIFICATE");
            return new TrustFirstCertificateTlsPolicy(new KeystoreCertificateRepository(sslKeystore));
        }
        else if( tlsPolicyName.equals("TRUST_KNOWN_CERTIFICATE") ) {
            log.info("TLS Policy: TRUST_KNOWN_CERTIFICATE");
            return new TrustKnownCertificateTlsPolicy(new KeystoreCertificateRepository(sslKeystore));
        }
        else if( tlsPolicyName.equals("INSECURE") ) {
            log.warn("TLS Policy: INSECURE");
            return new InsecureTlsPolicy();
        }
        else {
            // unrecognized 1.1 policy defined, so use a secure default
            log.error("Unknown TLS Policy Name: {}", tlsPolicyName);
            return new TrustCaAndVerifyHostnameTlsPolicy(new KeystoreCertificateRepository(sslKeystore));
        }
    }
    /*
    public final void setBaseURL(URL baseURL) {
        this.baseURL = baseURL;
    }
    public final void setKeystore(SimpleKeystore keystore) {
        this.keystore = keystore;
    }    
    public final void setRequireTrustedCertificate(boolean value) {
        requireTrustedCertificate = value;
    }
    public final void setVerifyHostname(boolean value) {
        verifyHostname = value;
    }
    * 
    */
    
    /**
     * Used in Mt Wilson 1.0-RC2
     * 
     * Base URL and other configuration must already be set before calling this
     * method.
     *
     * @param protocol either "http" or "https"
     * @param port such as 80 for http, 443 for https
     * @throws KeyManagementException
     * @throws NoSuchAlgorithmException 
     */
    /*
    private SchemeRegistry initSchemeRegistry(String protocol, int port) throws KeyManagementException, NoSuchAlgorithmException {
        SchemeRegistry sr = new SchemeRegistry();
        if( "http".equals(protocol) ) {
            Scheme http = new Scheme("http", port, PlainSocketFactory.getSocketFactory());
            sr.register(http);
        }
        if( "https".equals(protocol) ) {
            X509HostnameVerifier hostnameVerifier; // secure by default (default verifyHostname = true)
            X509TrustManager trustManager; // secure by default, using Java's implementation which verifies the peer and using java's trusted keystore as default if user does not provide a specific keystore
            if( verifyHostname ) {
                hostnameVerifier = SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
            }
            else { // if( !config.getBoolean("mtwilson.api.ssl.verifyHostname", true) ) {
                hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            }
            
            if( requireTrustedCertificate && keystore != null ) {
                trustManager = SslUtil.createX509TrustManagerWithKeystore(keystore);                
            }
            else if( requireTrustedCertificate ) { // config.getBoolean("mtwilson.api.ssl.requireTrustedCertificate", true) ) {
                //String truststore = config.getString("mtwilson.api.keystore", System.getProperty("javax.net.ssl.trustStorePath")); // if null use default java trust store...
                //String truststorePassword = config.getString("mtwilson.api.keystore.password", System.getProperty("javax.net.ssl.trustStorePassword"));
//                String truststore = System.getProperty("javax.net.ssl.trustStorePath");
                String truststore = System.getProperty("javax.net.ssl.trustStore");
                String truststorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
                
                // create a trust manager using only our trusted ssl certificates
                if( truststore == null || truststorePassword == null ) {
                    throw new IllegalArgumentException("Require trusted certificates is enabled but truststore is not configured");
                }
                keystore = new SimpleKeystore(new File(truststore), truststorePassword);
                trustManager = SslUtil.createX509TrustManagerWithKeystore(keystore);
            }
            else {
                // user does not want to ensure certificates are trusted, so use a no-op trust manager
                trustManager = new NopX509TrustManager();
            }
            SSLContext sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(null, new X509TrustManager[] { trustManager }, null); // key manager, trust manager, securerandom
            SSLSocketFactory sf = new SSLSocketFactory(
                sslcontext,
                hostnameVerifier
                );
            Scheme https = new Scheme("https", port, sf); // URl defaults to 443 for https but if user specified a different port we use that instead
            sr.register(https);            
        }        
        return sr;
    }
    */
    
    /**
     * Used in Mt Wilson 1.1
     * 
     * @param protocol
     * @param port
     * @param policy
     * @return
     * @throws KeyManagementException
     * @throws NoSuchAlgorithmException 
     */
    private SchemeRegistry initSchemeRegistryWithPolicy(String protocol, int port, ApacheTlsPolicy policy) throws KeyManagementException, NoSuchAlgorithmException {
        SchemeRegistry sr = new SchemeRegistry();
        if( "http".equals(protocol) ) {
            Scheme http = new Scheme("http", port, PlainSocketFactory.getSocketFactory());
            sr.register(http);
        }
        if( "https".equals(protocol) ) {
            SSLContext sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(null, new X509TrustManager[] { policy.getTrustManager() }, null); // key manager, trust manager, securerandom
            SSLSocketFactory sf = new SSLSocketFactory(
                sslcontext,
                policy.getApacheHostnameVerifier()
                );
            Scheme https = new Scheme("https", port, sf); // URl defaults to 443 for https but if user specified a different port we use that instead
            sr.register(https);            
        }        
        return sr;
    }
    
    
    /**
     * Call this to ensure that all HTTP connections and files are closed
     * when your are done using the API Client.
     */
    @Override
    public void close() {
        connectionManager.shutdown();
    }
    
    private MediaType createMediaType(HttpResponse response) {
        if( response.getFirstHeader("Content-Type") != null ) {
            String contentType = response.getFirstHeader("Content-Type").getValue();
            if( "text/plain".equals(contentType) ) {
                return MediaType.TEXT_PLAIN_TYPE;
            }
            if( "text/xml".equals(contentType) ) {
                return MediaType.TEXT_XML_TYPE;
            }
            if( "text/html".equals(contentType) ) {
                return MediaType.TEXT_HTML_TYPE;
            }
            if( "application/json".equals(contentType) ) {
                return MediaType.APPLICATION_JSON_TYPE;
            }
            if( "application/xml".equals(contentType) ) {
                return MediaType.APPLICATION_XML_TYPE;
            }
            if( "application/octet-stream".equals(contentType) ) {
                return MediaType.APPLICATION_OCTET_STREAM_TYPE;
            }
            log.error("Got unsupported content type from server: "+contentType);
            return MediaType.APPLICATION_OCTET_STREAM_TYPE;
        }
        log.error("Missing content type header from server, assuming application/octet-stream");
        return MediaType.APPLICATION_OCTET_STREAM_TYPE;
    }
    
    private ApiResponse readResponse(HttpResponse response) throws IOException {
        MediaType contentType = createMediaType(response);
        byte[] content = null;
        HttpEntity entity = response.getEntity();
        if( entity != null ) {
            InputStream contentStream = entity.getContent();
            if( contentStream != null ) {
                content = IOUtils.toByteArray(contentStream);
                contentStream.close();
            }
        }
        return new ApiResponse(response.getStatusLine().getStatusCode(), response.getStatusLine().getReasonPhrase(), contentType, content);
    }
    
    public ApiResponse get(String requestURL) throws IOException, ApiException, SignatureException {
        log.debug("GET url: {}", requestURL);        
        HttpGet request = new HttpGet(requestURL);
        // send the request and print the response
        HttpResponse httpResponse = httpClient.execute(request);
        ApiResponse apiResponse = readResponse(httpResponse);
        request.releaseConnection();
        return apiResponse;
    }

    public ApiResponse delete(String requestURL) throws IOException, SignatureException {
        log.debug("DELETE url: {}", requestURL);
        HttpDelete request = new HttpDelete(requestURL);
        // send the request and print the response
        HttpResponse httpResponse = httpClient.execute(request);
        ApiResponse apiResponse = readResponse(httpResponse);
        request.releaseConnection();
        return apiResponse;
    }
    
    public ApiResponse put(String requestURL, ApiRequest message) throws IOException, SignatureException {
        log.debug("PUT url: {}", requestURL);
        log.debug("PUT content: {}", message == null ? "(empty)" : message.content);
        HttpPut request = new HttpPut(requestURL);
        if( message != null && message.content != null ) {
            request.setEntity(new StringEntity(message.content, ContentType.create(message.contentType.toString(), "UTF-8")));
        }
        HttpResponse httpResponse = httpClient.execute(request);
        ApiResponse apiResponse = readResponse(httpResponse);
        request.releaseConnection();
        return apiResponse;
    }
    
    public ApiResponse post(String requestURL, ApiRequest message) throws IOException, SignatureException {
        log.debug("POST url: {}", requestURL);
        log.debug("POST content: {}", message == null ? "(empty)" : message.content);
        HttpPost request = new HttpPost(requestURL);
        if( message != null && message.content != null ) {
            request.setEntity(new StringEntity(message.content, ContentType.create(message.contentType.toString(), "UTF-8")));
        }
        HttpResponse httpResponse = httpClient.execute(request);
        ApiResponse apiResponse = readResponse(httpResponse);
        request.releaseConnection();
        return apiResponse;
    }
}
