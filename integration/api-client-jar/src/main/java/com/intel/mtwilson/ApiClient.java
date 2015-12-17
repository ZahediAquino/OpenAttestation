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
import com.intel.mtwilson.util.crypto.RsaCredential;
import com.intel.mtwilson.tls.TlsPolicy;
import com.intel.mountwilson.as.hostmanifestreport.data.HostManifestReportType;
import com.intel.mountwilson.as.hosttrustreport.data.HostsTrustReportType;
import com.intel.mtwilson.util.crypto.SimpleKeystore;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.datatypes.xml.HostTrustXmlResponse;
import com.intel.mtwilson.datatypes.xml.HostTrustXmlResponseList;
import com.intel.mtwilson.io.ConfigurationUtil;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import static javax.ws.rs.core.MediaType.*;
import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.net.URLCodec;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.MapConfiguration;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class has many constructors to provide convenience for developers. 
 * However, too many options may be confusing.
 * Based on developer feedback, we should retain the most useful constructors
 * and deprecate the rest. 
 * Two candidates for KEEPING are (File) and (URL,Hmac/RsaCredential,SimpleKeystore).
 * Those two constructors provide the two extremes: with (File), all properties in a file,
 * developer specifies the path for easy integration into any system); with
 * (URL,Hmac/RsaCredential,SimpleKeystore) a developer is able to instantiate a secure
 * ApiClient completely in Java without requiring a  configuration file (it will enable
 * requireTrustedCertificate and verifyHostname).
 * @since 0.5.2
 * @author jbuhacoff
 */
public class ApiClient implements AttestationService, WhitelistService, AssetTagService {
    private static Logger log = LoggerFactory.getLogger(ApiClient.class);
//    private JerseyHttpClient httpClient;
    private ApacheHttpClient httpClient;
    private URL baseURL; // https://attestationservice.local:443
    private String attestationServicePath = "/AttestationService/resources"; // or /AttestationHandler/resources
    private String whitelistServicePath = "/WLMService/resources";
//    private Credential credential;
//    private HmacCredential hmacCredential;
//    private RsaCredential rsaCredential;
    protected static final ObjectMapper mapper = new ObjectMapper();
    private static final String defaultConfigurationFilename = "mtwilson.properties";
    private ClassLoader jaxbClassLoader = null;
    
    private SimpleKeystore keystore;
        
    /**
     * Loads configuration from the specified file. 
     * 
     * The configuration file must include the web service base URL and 
     * authentication information.
     * 
     * @param configurationFilename 
     * @throws ClientException that may wrap NoSuchAlgorithmException, KeyManagementException, MalformedURLException, UnsupportedEncodingException, KeyStoreException, IOException, UnrecoverableEntryException, or CertificateException
     * @throws IOException if there was a problem reading the specified file
     */
    public ApiClient(File configurationFile) throws ClientException, IOException {
        this(ConfigurationUtil.fromPropertiesFile(configurationFile));
        log.info("Initialized with configuration file: "+configurationFile.getAbsolutePath());
    }
    
    /**
     * Instantiates an ApiClient using the provided configuration. It must
     * include the base URL and authentication credentials.
     * 
     * @param config
     * @throws ClientException that may wrap NoSuchAlgorithmException, KeyManagementException, MalformedURLException, UnsupportedEncodingException, KeyStoreException, IOException, UnrecoverableEntryException, or CertificateException
     */
    public ApiClient(Configuration config) throws ClientException {
        try {
        setBaseURL(config.getString("mtwilson.api.baseurl"));
        log.debug("Base URL: "+baseURL.toExternalForm());
        /*
        httpClient = new JerseyHttpClient(baseURL.toExternalForm(), config.getString("mtwilson.api.clientId"), config.getString("mtwilson.api.secretKey"));
        */
        setKeystore(config);
        setHttpClientWithConfig(config);
        }
        catch(Exception e) {
            throw new ClientException("Cannot initialize client", e);
        }
    }
    

    /**
     * Instantiates an ApiClient using the provided base URL and authentication
     * credential, and using configuration information from the provided properties.
     * 
     * @param baseURL
     * @param credential
     * @param properties
     * @throws ClientException that may wrap NoSuchAlgorithmException, KeyManagementException, MalformedURLException, UnsupportedEncodingException, KeyStoreException, IOException, or CertificateException
     */
    public ApiClient(URL baseURL, Properties properties) throws ClientException {
        try {
        setBaseURL(baseURL);
        Configuration config = new MapConfiguration(properties);
        setKeystore(config);
        log.debug("Base URL: "+baseURL.toExternalForm());
        httpClient = new ApacheHttpClient(baseURL, keystore, config);
        }
        catch(Exception e) {
            throw new ClientException("Cannot initialize client", e);
        }
    }


    /**
     * This constructor automatically enables requireTrustedCertificate and verifyHostname 
     * because a keystore is specified. If you want to specify a keystore yet not
     * require trusted certificates or verify hostnames, use the Configuration constructor.
     * @param baseURL
     * @param credential
     * @param keystore
     * @throws ClientException that may wrap NoSuchAlgorithmException, KeyManagementException, MalformedURLException, UnsupportedEncodingException, KeyStoreException, IOException, or CertificateException
     */
    public ApiClient(URL baseURL, SimpleKeystore keystore, Configuration config) throws ClientException {
        try {
        setBaseURL(baseURL);
        setKeystore(keystore);
        log.debug("Base URL: "+baseURL.toExternalForm());
        httpClient = new ApacheHttpClient(baseURL, keystore, config);
        }
        catch(Exception e) {
            throw new ClientException("Cannot initialize client", e);
        }
    }
    
    private void setBaseURL(URL url) {
        if( url == null ) {
            throw new IllegalArgumentException("Base URL must not be null");
        }
        baseURL = url;
    }
    private void setBaseURL(String url) throws MalformedURLException {
        if( url == null ) {
            throw new IllegalArgumentException("Base URL must not be null");
        }
        baseURL = new URL(url);
    }
    
    /**
     * Prefers RSA-SHA256 authentication (mtwilson.api.keystore and mtwilson.api.key.alias),
     * then HMAC-SHA256 authentication (mtwilson.api.clientId and mtwilson.api.secretKey),
     * then no authentication.
     * 
     * @param config
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableEntryException
     * @throws IOException
     * @throws KeyManagementException 
     */
    private void setHttpClientWithConfig(Configuration config) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, IOException, KeyManagementException {
        setKeystore(config);
        httpClient = new ApacheHttpClient(baseURL, keystore, config);
    }
    
    private void setKeystore(Configuration config) throws KeyManagementException {
        if( config != null && config.containsKey("mtwilson.api.keystore") && config.containsKey("mtwilson.api.keystore.password") ) {
            keystore = new SimpleKeystore(new File(config.getString("mtwilson.api.keystore")), config.getString("mtwilson.api.keystore.password"));
        }
        else if( config != null && config.containsKey("javax.net.ssl.keyStore") && config.containsKey("javax.net.ssl.keyStorePassword") ) {
            keystore = new SimpleKeystore(new File(config.getString("javax.net.ssl.keyStore")), config.getString("javax.net.ssl.keyStorePassword"));            
        }
    }
    
    public final void setKeystore(SimpleKeystore keystore) {
        this.keystore = keystore;
    }

    /**
     * Some environments such as OSGi require the use of their own ClassLoader
     * when using JAXB. Use this method to set the ClassLoader that should be
     * used when deserializing XML responses with JAXB.
     * The default is to use the system class loader.
     * @param classLoader to use with JAXB, or null to use the default class loader
     */
    public void setJaxbClassLoader(ClassLoader classLoader) {
        jaxbClassLoader = classLoader;
    }
        
    /**
     * Call this to ensure that all HTTP connections and files are closed
     * when your are done using the API Client.
     */
    public void close() {
//        connectionManager.shutdown();
    }
    
    private String querystring(MultivaluedMap<String,String> query) {
        URLCodec urlsafe = new URLCodec("UTF-8");
        String queryString = "";
        ArrayList<String> params = new ArrayList<String>();
        for( String key : query.keySet() ) {
            if( query.get(key) == null ) {
                params.add(key+"=");
            }
            else {
                for( String value : query.get(key) ) {
                    try {
                        params.add(key+"="+urlsafe.encode(value)); // XXX assumes that the keys don't have any special characters
                    } catch (EncoderException ex) {
                        log.error("Cannot encode query parameter: {}", value, ex);
                    }
                }
            }
            queryString = StringUtils.join(params, "&");
        }
        return queryString;
    }
    
    private String asurl(String apiPath) {
        return baseURL.toExternalForm().concat(attestationServicePath).concat(apiPath);
    }
    private String asurl(String apiPath, MultivaluedMap<String,String> query) {
        return baseURL.toExternalForm().concat(attestationServicePath).concat(apiPath).concat("?").concat(querystring(query));
    }

    private String wlmurl(String apiPath) {
        return baseURL.toExternalForm().concat(whitelistServicePath).concat(apiPath);
    }
    
    private String wlmurl(String apiPath, MultivaluedMap<String,String> query) {
        return baseURL.toExternalForm().concat(whitelistServicePath).concat(apiPath).concat("?").concat(querystring(query));
    }

    private ApiResponse httpGet(String path) throws IOException, ApiException, SignatureException {
        return httpClient.get(path);
    }
    private ApiResponse httpDelete(String path) throws IOException, ApiException, SignatureException {
        return httpClient.delete(path);
    }
    private ApiResponse httpPut(String path, ApiRequest body) throws IOException, ApiException, SignatureException {
        return httpClient.put(path, body);
    }
    private ApiResponse httpPost(String path, ApiRequest body) throws IOException, ApiException, SignatureException {
        return httpClient.post(path, body);
    }
    
    // only call this if the Http Status is NOT OK in order to convert the response to an ApiException
    private ApiException error(ApiResponse response) throws IOException, ApiException {
        if( response.contentType.isCompatible(APPLICATION_JSON_TYPE) ) {
            // a json error response from the web application. we need to provide the error message to the user.
            ErrorResponse errorResponse;
            try {
                log.debug("Parsing JSON error response: "+new String(response.content, "UTF-8"));
                errorResponse = json(new String(response.content, "UTF-8"), ErrorResponse.class);
            }
            catch(Exception e) {
                // cannot parse the json response, so include the entire response for the user. we ignore the exception "e" because it just means we couldn't parse the response.
                return new ApiException(response, "Cannot parse response: "+e.getMessage(), ErrorCode.UNKNOWN_ERROR);
            }
            return new ApiException(response, errorResponse.getErrorMessage(), ErrorCode.valueOf(errorResponse.getErrorCode()));
        }
        else if( response.contentType.isCompatible(TEXT_HTML_TYPE) ) {
            // typically html error message generated by web application container; we can ignore the html content because its generic
            String errorMessage = response.httpReasonPhrase;
            HtmlErrorParser errorParser = new HtmlErrorParser(new String(response.content, "UTF-8"));
            if( errorParser.getRootCause() != null ) {
                errorMessage = errorMessage.concat(": "+errorParser.getRootCause());
            }
            return new ApiException(response, errorMessage, httpErrorCode(response.httpStatusCode));
        }
        else {
            // a non-json, non-html error response from the web application: so we include the response in the exception message. http 401 unauthorized responses are included here.
            return new ApiException(response, new String(response.content, "UTF-8"), httpErrorCode(response.httpStatusCode));
        }
    }
    
    private ErrorCode httpErrorCode(int httpErrorCode) {
        ErrorCode e;
        switch(httpErrorCode) {
            case 200: e = ErrorCode.OK; break;
            case 400: e = ErrorCode.HTTP_INVALID_REQUEST; break;
            case 401: e = ErrorCode.HTTP_UNAUTHORIZED; break;
            case 403: e = ErrorCode.HTTP_FORBIDDEN; break;
            case 404: e = ErrorCode.HTTP_NOT_FOUND; break;
            case 500: e = ErrorCode.HTTP_INTERNAL_SERVER_ERROR; break;                
            default: e = ErrorCode.UNKNOWN_ERROR; break;
        }
        return e;
    }
    
    private byte[] content(ApiResponse response) throws IOException, ApiException {
        log.trace("Status: {} {}", response.httpStatusCode, response.httpReasonPhrase);
        log.trace("Content-Type: {}", response.contentType.toString());
        log.trace("Content: {}", response.content);
        if( response.httpStatusCode == HttpStatus.SC_OK ) {
            return response.content;
        }
        else {
            throw error(response);
        }
    }
    
    // xxx: don't know if it's better to define just one serialize method or to have each api call choose what form its response should come in...
    // one call is more flexible and easier to maintain...
    // this gets called only for successful responses; error codes 400, 500, etc. are thrown as ApiException by the http client so we'd never get to this.
    /*
    private <T> T deserialize(HttpResponse response, Class<T> valueType) throws IOException, ApiException {
        String body = responsebody(response);
        String contentType = response.getEntity() != null && response.getEntity().getContentType() != null ? response.getEntity().getContentType().getValue() : "";
        if( "application/json".equals(contentType) ) {
            return fromJSON(body, valueType);
        }
        else {
            return null;
        }
    }*/
    
    private String text(ApiResponse response) throws IOException, ApiException {
        return new String(content(response), "UTF-8");
    }

    private byte[] binary(ApiResponse response) throws IOException, ApiException {
        return content(response);
    }
    
    private <T> T json(ApiResponse response, Class<T> valueType) throws IOException, ApiException {
        if( response.httpStatusCode == HttpStatus.SC_OK && response.contentType.isCompatible(APPLICATION_JSON_TYPE) ) {
            return json(new String(response.content, "UTF-8"), valueType);
        }
        else if( response.httpStatusCode == HttpStatus.SC_OK ) {
            log.error("Unexpected content type {} in response", response.contentType.toString());
            throw new ApiException(response, "Unexpected content type in response: "+response.contentType.toString());
        }
        else {
            throw error(response);
        }
    }
    
    
    private <T> T json(String document, Class<T> valueType) throws IOException, ApiException {
        if( document == null ) {
            throw new ApiException("Response from server has no content");
        }
        try {
            return mapper.readValue(document, valueType);
        }
        catch(org.codehaus.jackson.JsonParseException e) {
            log.error("Cannot parse response: "+document);
            throw new ApiException("Cannot parse response: "+document, e);
        }        
    }
    
    private <T> T fromJSON(ApiResponse response, Class<T> valueType) throws IOException, ApiException {
        return json(response, valueType);
    }
    
    private ApiRequest toJSON(Object value) throws IOException {
        return new ApiRequest(APPLICATION_JSON_TYPE, mapper.writeValueAsString(value));
    }

    private <T> T xml(ApiResponse response, Class<T> valueType) throws IOException, ApiException {
        if( response.httpStatusCode == HttpStatus.SC_OK && response.contentType.isCompatible(APPLICATION_XML_TYPE) ) { // XXX or isCompatible(TEXT_XML_TYPE)
            return xml(new String(response.content, "UTF-8"), valueType);                
        }
        else if( response.httpStatusCode == HttpStatus.SC_OK ) {
            log.error("Unexpected content type {} in response", response.contentType.toString());
            throw new ApiException(response, "Unexpected content type in response: "+response.contentType.toString());
        }
        else {
            throw error(response);
        }
    }
    
    private <T> T xml(String document, Class<T> valueType) throws IOException, ApiException {
        try {
            JAXBContext jc;
            if( jaxbClassLoader != null ) {
                jc = JAXBContext.newInstance( valueType.getPackage().getName(), jaxbClassLoader );
            }
            else {
                jc = JAXBContext.newInstance( valueType.getPackage().getName() );
            }
            Unmarshaller u = jc.createUnmarshaller();
            JAXBElement<T> doc = (JAXBElement<T>)u.unmarshal( new StreamSource( new StringReader( document ) ) );
            return doc.getValue();
        }
        catch(JAXBException e) {
            throw new ApiException("Cannot parse response: "+document, e);
        }
    }
    
    private <T> T fromXML(ApiResponse response, Class<T> valueType) throws IOException, ApiException, JAXBException {
        return xml(response, valueType);
    }
    
    /**
     * 
     * @param response an HttpResponse from GET, PUT, POST, or DELETE request
     * @return String content from server response
     * @throws IOException 
     */
    /*
    private String plaintext(HttpResponse response) throws IOException {
        return IOUtils.toString(response.getEntity().getContent(), "UTF-8");
    }
      */  
    // Attestation Service API
    
    /**
     * javax.ws.rs.core.MediaType.APPLICATION_JSON  application/json
     * @param hostname 
     */
    @Override
    public HostLocation getHostLocation(Hostname hostname) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        HostLocation location = fromJSON(httpGet(asurl("/hosts/location", query)), HostLocation.class);
        return location;
    }
    
    @Override
    public boolean addHostLocation(HostLocation hostLocObj) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(asurl("/hosts/location"), toJSON(hostLocObj)));
        return "true".equals(result);
    }

    /**
     * 
     * @param trustStatusString like "BIOS:1,VMM:1" from API version 0.5.1
     * @return 
     */
    private HostTrustStatus parseHostTrustStatusString(String trustStatusString) {
            HostTrustStatus trustStatus = new HostTrustStatus();        
            String[] parts = trustStatusString.split(",");
            for (String part : parts) {
                    String[] subParts = part.split(":");
                    if (subParts[0].equals("BIOS")) {
                            trustStatus.bios = subParts[1].equals("1");
                    }
                    else if(subParts[0].equals("VMM")) {
                            trustStatus.vmm = subParts[1].equals("1");
                    }
                    else if(subParts[0].equals("ATag")) {
                            trustStatus.asset_tag = subParts[1].equals("1");
                    }
            }
            return trustStatus;
    }
    
    /**
     * /hosts/trust?hostname=1.2.3.4
     * Response is PLAINTEXT ("BIOS:1,VMM:1") but needs to be changed to JSON on server  (todo) so we support both.
     * @param hostname
     * @return 
     */
    @Override
    public HostTrustResponse getHostTrust(Hostname hostname) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        // need to support both formats:  "BIOS:1,VMM:1" from 0.5.1 and JSON from 0.5.2
        log.debug("Getting status for host: {}", hostname);
        ApiResponse response = httpClient.get(asurl("/hosts/trust", query));
        log.debug("Server Response: {}",text(response));
        HostTrustResponse trust;
        if( response.httpStatusCode == HttpStatus.SC_OK ) {            
            if( APPLICATION_JSON_TYPE.equals(response.contentType) ) {
                trust = json(response, HostTrustResponse.class);            
            }
            else if( TEXT_PLAIN_TYPE.equals(response.contentType) ) {
                trust = new HostTrustResponse(hostname, parseHostTrustStatusString(text(response)));
            }
            else {
                throw new ApiException(response, "Unexpected content type in response: "+response.contentType, ErrorCode.UNKNOWN_ERROR.getErrorCode());
            }
            return trust;
        }
        else {
            throw error(response);
        }
    }

    @Override
    public boolean addHost(TxtHost host) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(asurl("/hosts"), toJSON(new TxtHostRecord(host))));
        return "true".equals(result);
    }

    @Override
    public boolean updateHost(TxtHost host) throws IOException, ApiException, SignatureException {
        //HostResponse added = fromJSON(httpPut(asurl("/hosts"), toJSON(new TxtHostRecord(host))), HostResponse.class);
        String added = text(httpPut(asurl("/hosts"), toJSON(new TxtHostRecord(host))));
        //return added;
        return "true".equals(added);
    }

    @Override
    public boolean deleteHost(Hostname hostname) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        //HostResponse deleted = fromJSON(httpDelete(asurl("/hosts", query)), HostResponse.class);
        String deleted = text(httpDelete(asurl("/hosts", query)));
        return "true".equals(deleted);
        //return deleted;        
    }

    @Override
    public AttestationReport getAttestationFailureReport(Hostname hostname) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        query.add("failure_only", Boolean.toString(true));
        AttestationReport report = fromJSON(httpGet(asurl("/hosts/reports/attestationreport", query)), AttestationReport.class);
        return report;        
        
    }

    @Override
    public AttestationReport getAttestationReport(Hostname hostname) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        AttestationReport report = fromJSON(httpGet(asurl("/hosts/reports/attestationreport", query)), AttestationReport.class);
        return report;        
    }

    @Override
    public X509Certificate getTlsCertificateForTrustedHost(Hostname hostname) throws IOException, ApiException, SignatureException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    // this is required so that the jackson mapper will create an instance of ListMleData (List<MleData>) instead of creating an instance of List<LinkedHashMap>
    public static class ListHostData extends ArrayList<TxtHostRecord> { };
    
    @Override
    public List<TxtHostRecord> queryForHosts(String searchCriteria) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("searchCriteria", searchCriteria); 
        ListHostData results = fromJSON(httpGet(asurl("/hosts", query)), ListHostData.class);
        return results;                
    }
    
    @Override
    public List<TxtHostRecord> queryForHosts(String searchCriteria, boolean includeHardware) throws IOException, ApiException, SignatureException {
        log.debug("queryForHosts includeHardwareUuid["+includeHardware+"]");
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("searchCriteria", searchCriteria);        
        query.add("includeHardwareUuid",String.valueOf(includeHardware));
        //query.add("includeTlsPolicy",String.valueOf(false));
        ListHostData results = fromJSON(httpGet(asurl("/hosts", query)), ListHostData.class);
        return results;
    }    

    /**
     * javax.ws.rs.core.MediaType.APPLICATION_XML   application/xml
     * @param hostnames 
     */
    @Override
    public OpenStackHostTrustLevelReport pollHosts(List<Hostname> hostnames) throws IOException, ApiException, SignatureException {
        OpenStackHostTrustLevelQuery input = new OpenStackHostTrustLevelQuery();
        input.hosts = hostnames.toArray(new Hostname[0]);
        OpenStackHostTrustLevelReport output = fromJSON(httpPost(asurl("/PollHosts"), toJSON(input)), OpenStackHostTrustLevelReport.class);
        return output;
    }

    @Override
    public HostsTrustReportType getHostTrustReport (List<Hostname> hostnames) throws IOException, ApiException, SignatureException, JAXBException {
        String hostNamesCSV = StringUtils.join(hostnames, ",");
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostNames", hostNamesCSV);
        HostsTrustReportType report = fromXML(httpGet(asurl("/hosts/reports/trust", query)), HostsTrustReportType.class);
        return report;
    }

    @Override
    public HostManifestReportType getHostManifestReport (Hostname hostname) throws IOException, ApiException, SignatureException, JAXBException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        HostManifestReportType report = fromXML(httpGet(asurl("/hosts/reports/trust", query)), HostManifestReportType.class);        
        return report;
    }
    

    /**
     * @deprecated this method is used only by OpenSourceVMMHelper which is being replaced by IntelHostAgent; also the service implementation of this method only supports hosts with trust agents (even though vmware hosts also have their own attestation report)
     * @param hostname
     * @return
     * @throws IOException
     * @throws ApiException
     * @throws SignatureException 
     */
    @Override
    public String getHostAttestationReport(Hostname hostname) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        String attReport = text(httpGet(asurl("/hosts/reports/attestation", query)));
        return attReport;
    }

    // Whitelist Management API
    @Override
    public boolean addMLE(MleData mle) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(wlmurl("/mles"), toJSON(mle)));
        return "true".equals(result);
    }

    @Override
    public boolean updateMLE(MleData mle) throws IOException, ApiException, SignatureException {
        String result = text(httpPut(wlmurl("/mles"), toJSON(mle)));
        return "true".equals(result);        
    }


    // this is required so that the jackson mapper will create an instance of ListMleData (List<MleData>) instead of creating an instance of List<LinkedHashMap>
    public static class ListMleData extends ArrayList<MleData> { };
    
    @Override
    public List<MleData> searchMLE(String name) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("searchCriteria", name);        
        ListMleData results = fromJSON(httpGet(wlmurl("/mles", query)), ListMleData.class);
        return results;        
    }

    /**
     * Also known as GetMLEDetails
     * 
     * @param criteria 
     */
    @Override
    public MleData getMLEManifest(MLESearchCriteria criteria) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("mleName", criteria.mleName);        
        query.add("mleVersion", criteria.mleVersion);        
        query.add("osName", criteria.osName);        
        query.add("osVersion", criteria.osVersion);        
        query.add("oemName", criteria.oemName);        
        MleData mle = fromJSON(httpGet(wlmurl("/mles/manifest", query)), MleData.class);
        return mle;
    }

    @Override
    public boolean deleteMLE(MLESearchCriteria criteria) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("mleName", criteria.mleName);        
        query.add("mleVersion", criteria.mleVersion);        
        query.add("osName", criteria.osName);        
        query.add("osVersion", criteria.osVersion);        
        query.add("oemName", criteria.oemName);        
        String result = fromJSON(httpDelete(wlmurl("/mles", query)), String.class);        
        return "true".equals(result);        
    }

    // this is required so that the jackson mapper will create an instance of ListOemData (List<OemData>) instead of creating an instance of List<LinkedHashMap>
    public static class ListOemData extends ArrayList<OemData> { };
    
    @Override
    public List<OemData> listAllOEM() throws IOException, ApiException, SignatureException {
        ListOemData results = fromJSON(httpGet(wlmurl("/oem")), ListOemData.class);
        return results;                
    }

    @Override
    public boolean addOEM(OemData oem) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(wlmurl("/oem"), toJSON(oem)));
        return "true".equals(result);                
    }

    @Override
    public boolean updateOEM(OemData oem) throws IOException, ApiException, SignatureException {
        String result = text(httpPut(wlmurl("/oem"), toJSON(oem)));
        return "true".equals(result);                
        
    }

    @Override
    public boolean deleteOEM(String name) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("Name", name);        
        String result = text(httpDelete(wlmurl("/oem", query))); 
        return "true".equals(result);                
    }

    // this is required so that the jackson mapper will create an instance of ListOsData (List<OsData>) instead of creating an instance of List<LinkedHashMap>
    public static class ListOsData extends ArrayList<OsData> { };
   
    @Override
    public List<OsData> listAllOS() throws IOException, ApiException, SignatureException {
        //ArrayList<OsData> results = fromJSON(GET(wlmurl("/os")), ArrayList.class);
        ListOsData results = fromJSON(httpGet(wlmurl("/os")), ListOsData.class);
        return results;                        
    }

    @Override
    public boolean updateOS(OsData os) throws IOException, ApiException, SignatureException {
        String result = text(httpPut(wlmurl("/os"), toJSON(os)));
        return "true".equals(result);                        
    }

    @Override
    public boolean addOS(OsData os) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(wlmurl("/os"), toJSON(os)));
        return "true".equals(result);                
        
    }

    @Override
    public boolean deleteOS(OsData os) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("Name", os.getName());        
        query.add("Version", os.getVersion());        
        String result = text(httpDelete(wlmurl("/os", query))); 
        return "true".equals(result);        
    }
    
    /**
     * Added By: Sudhir on June 26, 2012
     * 
     * Process the add request into the PCR manifest table.
     * 
     * @param pcrObj : White List data to be added to the PCR Manifest table
     * NOTE: OS Details need to be provided only when the associated MLE is of VMM type. 
     * For MLEs of BIOS type OEM Details have to be provided
     * @return : "true" if success or else exception.
     * @throws IOException
     * @throws ApiException
     * @throws SignatureException 
     */    
    @Override
    public boolean addPCRWhiteList(PCRWhiteList pcrObj) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(wlmurl("/mles/whitelist/pcr"), toJSON(pcrObj)));
        return "true".equals(result);                
    }

    /**
     * Added By: Sudhir on June 26, 2012
     * 
     * Processes the update request into the PCR manifest table.
     * 
     * @param pcrObj : White List data to be updated in the PCR Manifest table.
     * NOTE: OS Details need to be provided only when the associated MLE is of VMM type. 
     * For MLEs of BIOS type OEM Details have to be provided
     * @return : "true" if success or else exception.
     * @throws IOException
     * @throws ApiException
     * @throws SignatureException 
     */
    @Override
    public boolean updatePCRWhiteList(PCRWhiteList pcrObj) throws IOException, ApiException, SignatureException {
        String result = text(httpPut(wlmurl("/mles/whitelist/pcr"), toJSON(pcrObj)));
        return "true".equals(result);                    
    }

    /**
     * Added By: Sudhir on June 26, 2012
     * 
     * Processes the delete request from the PCR manifest table.
     * 
     * @param pcrObj : White List data to be from the PCR Manifest table.
     * NOTE: PCR name along with MLE details need to be provided. No need to
     * specify PCR Digest value. OS Details need to be provided only when the 
     * associated MLE is of VMM type. For MLEs of BIOS type OEM Details have to be provided.
     * @return : "true" if success or else exception.
     * @throws IOException
     * @throws ApiException
     * @throws SignatureException 
     */
    @Override
    public boolean deletePCRWhiteList(PCRWhiteList pcrObj) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("pcrName", pcrObj.getPcrName());        
        query.add("mleName", pcrObj.getMleName());        
        query.add("mleVersion", pcrObj.getMleVersion());        
        query.add("osName", pcrObj.getOsName());        
        query.add("osVersion", pcrObj.getOsVersion());        
        query.add("oemName", pcrObj.getOemName());        
        String result = text(httpDelete(wlmurl("/mles/whitelist/pcr", query))); 
        return "true".equals(result);                
    }
            
    @Override
    public boolean addMleSource(MleSource mleSourceObj) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(wlmurl("/mles/source"), toJSON(mleSourceObj)));
        return "true".equals(result);                
    }

    @Override
    public boolean updateMleSource(MleSource mleSourceObj) throws IOException, ApiException, SignatureException {
        String result = text(httpPut(wlmurl("/mles/source"), toJSON(mleSourceObj)));
        return "true".equals(result);                    
    }

    @Override
    public boolean deleteMleSource(MleData mleDataObj) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("mleName", mleDataObj.getName());        
        query.add("mleVersion", mleDataObj.getVersion());        
        query.add("osName", mleDataObj.getOsName());        
        query.add("osVersion", mleDataObj.getOsVersion());        
        query.add("oemName", mleDataObj.getOemName());        
        String result = text(httpDelete(wlmurl("/mles/source", query))); 
        return "true".equals(result);                
    }
    
    @Override
    public String getMleSource(MleData mleDataObj) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("mleName", mleDataObj.getName());        
        query.add("mleVersion", mleDataObj.getVersion());        
        query.add("osName", mleDataObj.getOsName());        
        query.add("osVersion", mleDataObj.getOsVersion());        
        query.add("oemName", mleDataObj.getOemName());        
        String result = text(httpGet(wlmurl("/mles/source", query)));
        return result;                        
    }
    
    @Override
    public boolean importAssetTagCertificate(AssetTagCertCreateRequest aTagObj) throws IOException, ApiException, SignatureException {
        String result = text(httpPost(asurl("/assetTagCert"), toJSON(aTagObj)));
        return "true".equals(result);
    }
    
    @Override
    public boolean revokeAssetTagCertificate(AssetTagCertRevokeRequest aTagObj) throws IOException, ApiException, SignatureException {
        String result = text(httpPut(asurl("/assetTagCert"), toJSON(aTagObj)));
        return "true".equals(result);
    }
    
    @Override
    public String getSamlForHost(Hostname hostname) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        // By default we will get it from cache.
        query.add("force_verify", Boolean.toString(false));
        String saml = text(httpGet(asurl("/saml/assertions/host", query))); // NOTE: we are returning the raw XML document, we don't try to instantiate any Java object via the xml() funciton. The client can create a TrustAssertion object using this XML string in order to parse it.
        return saml;
    }
    @Override
    public String getSamlForHost(Hostname hostname, boolean forceVerify) throws IOException, ApiException, SignatureException {
        MultivaluedMap<String,String> query = new MultivaluedMapImpl();
        query.add("hostName", hostname.toString());
        query.add("force_verify", Boolean.toString(forceVerify));
        String saml = text(httpGet(asurl("/saml/assertions/host", query))); // NOTE: we are returning the raw XML document, we don't try to instantiate any Java object via the xml() funciton. The client can create a TrustAssertion object using this XML string in order to parse it.
        return saml;
    }
    /*
    @Override
    public List<HostTrustXmlResponse> getSamlForMultipleHosts(Set<Hostname> hostnames, boolean forceVerify) throws IOException, ApiException, SignatureException {
            // prepare the request
            log.info("LOGGING +++++++++++ hostnames.size: " + hostnames.size());
            log.info("LOGGING +++++++++++ forceVerify" + forceVerify);
            String hostnamesCSV = StringUtils.join(hostnames, ","); // calls toString() on each hostname
            MultivaluedMap<String,String> query = new MultivaluedMapImpl();
            query.add("hosts", hostnamesCSV);
            query.add("force_verify", Boolean.toString(forceVerify));
            // make the request and parse the xml response
            //Print String URL
            HostTrustXmlResponseList list = xml(httpGet(asurl("/hosts/bulk/trust/saml", query)), HostTrustXmlResponseList.class);
            if(list.getHost() !=null) log.info("LOGGING +++++++++++ list.getHost().size()" + list.getHost().size()); else log.info("LOGGING +++++++++++ list.getHost() EVALUATES TO NULL!)");
            List<HostTrustXmlResponse> responses = list.getHost();
            for (Iterator<HostTrustXmlResponse> it = responses.iterator(); it.hasNext();) {
                 HostTrustXmlResponse  xmlResponse = it.next();
                 if(xmlResponse.getAssertion() != null) log.info("\"LOGGING +++++++++++ xmlResponse.getAssertion()" + xmlResponse.getAssertion()); else log.info("\"LOGGING +++++++++++ xmlResponse.getAssertion validates to NULL!");
                 
                
            }
            return list.getHost(); // get the list of <Host> elements inside the root <Hosts> element... it's an automatically generated method name. would have been nice if they named it getHostList()
        }*/
    public String getSamlForMultipleHosts(Set<Hostname> hostnames, boolean forceVerify) throws IOException, ApiException, SignatureException {
            // prepare the request
            String hostnamesCSV = StringUtils.join(hostnames, ","); // calls toString() on each hostname
            MultivaluedMap<String,String> query = new MultivaluedMapImpl();
            query.add("hosts", hostnamesCSV);
            query.add("force_verify", Boolean.toString(forceVerify));
            ApiResponse result = httpGet(asurl("/hosts/bulk/trust/saml", query));
            return new String(result.content, "UTF-8");
        }

}
