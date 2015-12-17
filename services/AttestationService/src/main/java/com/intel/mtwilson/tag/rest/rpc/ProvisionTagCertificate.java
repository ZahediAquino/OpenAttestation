/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.tag.rest.rpc;

//import com.intel.dcsg.cpg.io.ByteArrayResource;
import com.intel.mtwilson.datatypes.CryptoMediaType;
import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mtwilson.util.io.UUID;
import com.intel.mtwilson.util.io.Iso8601Date;
//import com.intel.mtwilson.My;
//import com.intel.mtwilson.MyFilesystem;
import com.intel.mtwilson.ApiException;
import com.intel.mtwilson.as.business.AssetTagCertBO;
import com.intel.mtwilson.crypto.CryptographyException;
import com.intel.mtwilson.datatypes.AssetTagCertAssociateRequest;
//import com.intel.mtwilson.datatypes.TxtHostRecord;
//import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
//import com.intel.mtwilson.launcher.ws.ext.V2;
//import com.intel.mtwilson.tag.PlaintextFilenameFilter;
import com.intel.mtwilson.tag.TagCertificateAuthority;
//import com.intel.mtwilson.tag.TagConfiguration;
import com.intel.mtwilson.tag.Util;
//import com.intel.mtwilson.tag.common.Global;
import com.intel.mtwilson.tag.common.X509AttrBuilder;
//import com.intel.mtwilson.tag.model.Certificate;
import com.intel.mtwilson.datatypes.CertificateCollection;
import com.intel.mtwilson.datatypes.CertificateFilterCriteria;
import com.intel.mtwilson.datatypes.CertificateRequest;
//import com.intel.mtwilson.tag.model.CertificateRequestLocator;
import com.intel.mtwilson.datatypes.X509AttributeCertificate;
//import com.intel.mtwilson.tag.rest.v2.repository.CertificateRepository;
//import com.intel.mtwilson.tag.rest.v2.repository.CertificateRequestRepository;
//import com.intel.mtwilson.tag.selection.SelectionBuilder;
import com.intel.mtwilson.tag.selection.xml.AttributeType;
import com.intel.mtwilson.tag.selection.xml.SelectionType;
//import com.intel.mtwilson.tag.selection.xml.SelectionsType;
//import import com.intel.mtwilson.ApiException;
import com.intel.mtwilson.tag.TagConfiguration;
import com.intel.mtwilson.tag.selection.xml.SelectionsType;
import com.intel.mtwilson.datatypes.CertificateRequestLocator;
import com.intel.mtwilson.datatypes.Certificate;
import com.intel.mtwilson.datatypes.TxtHostRecord;
import com.intel.mtwilson.launcher.ws.ext.RPC;
//import com.intel.mtwilson.datatypes.Util;
import com.intel.mtwilson.tag.common.Global;
import com.intel.mtwilson.tag.rest.repository.CertificateRepository;
import com.intel.mtwilson.util.crypto.Sha1Digest;
import com.sun.jersey.api.core.InjectParam;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
//import javax.ws.rs.BeanParam;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.cert.X509AttributeCertificateHolder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * See also AbstractRpcResource which does something similar with HTTP 202 Accepted
 * 
 * Currently supported request/response content-type combinations:
 * 
 * post application/json, accept application/pkix-cert  (binary)
 * post application/json, accept application/json
 * post application/xml, accept application/pkix-cert (binary)
 * post application/xml, accept application/xml
 * 
 * @author ssbangal and jbuhacoff
 */
//@V2
@Path("/tag-certificate-requests-rpc/provision")
@RPC("provision_tag_certificate")
//@JacksonXmlRootElement(localName="provision_tag_certificate")
@XmlRootElement(name="provision_tag_certificate")
public class ProvisionTagCertificate  {    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ProvisionTagCertificate.class);


   private CertificateRepository certificateRepository;
//   private CertificateRequestRepository repository;
//    
    public ProvisionTagCertificate() {
//        repository = new CertificateRequestRepository();
        certificateRepository = new CertificateRepository();
    }
    
//    protected CertificateRequestRepository getRepository() {
//        return repository;
//    }
//    
    protected boolean isAsync(HttpServletRequest request) {
        String async = request.getHeader("Asynchronous");
        return async != null && async.equalsIgnoreCase("true");
    }

    
//    protected void storeAsyncRequest(String subject, SelectionsType selections, HttpServletResponse response) throws IOException {
//            String xml = Util.toXml(selections);
//            byte[] plaintext = xml.getBytes(Charset.forName("UTF-8"));
//            CertificateRequest certificateRequest = new CertificateRequest();
//            certificateRequest.setId(new UUID());
//            certificateRequest.setStatus("New");
//            certificateRequest.setSubject(subject);
//            certificateRequest.setContent(plaintext);
//            certificateRequest.setContentType("application/xml"); 
//            getRepository().create(certificateRequest);
//            response.addHeader("Asynchronous", "true");
//            response.addHeader("Link", String.format("</tag-certificate-requests/%s>; rel=status", certificateRequest.getId().toString()));
////            response.addHeader("Link", String.format("</tag-certificates?certificateRequestIdEqualTo=%s>; rel=certificate", certificateRequest.getId().toString()));
//            response.setStatus(Response.Status.ACCEPTED.getStatusCode());        
//    }
//    
    protected Certificate storeTagCertificate(String subject, byte[] attributeCertificateBytes) throws IOException {
        X509AttributeCertificateHolder certificateHolder = new X509AttributeCertificateHolder(attributeCertificateBytes);
        Certificate certificate = Certificate.valueOf(certificateHolder.getEncoded());
        certificate.setId(new UUID());

        // Call into the certificate repository to create the new certificate entry in the database.
        certificateRepository.create(certificate);
        return certificate;
    }
//    
//    /**
//     * Returns the tag certificate bytes or null if one was not generated
//     * 
//     * @param subject
//     * @param selection may be null; the default selection will be used, if configured
//     * @param request
//     * @param response
//     * @return
//     * @throws IOException
//     */
    public Certificate createOne(String subject, SelectionsType selections, HttpServletRequest request, HttpServletResponse response) 
            throws IOException, ApiException, SignatureException, SQLException, IllegalArgumentException {        
//        TagConfiguration configuration = new TagConfiguration(My.configuration().getConfiguration());
//        TagCertificateAuthority ca = new TagCertificateAuthority(configuration);
          TagConfiguration configuration = new TagConfiguration(ASConfig.getConfiguration());
          TagCertificateAuthority ca = new TagCertificateAuthority(configuration);
        
        // if the subject is an ip address or hostname, resolve it to a hardware uuid with mtwilson - if the host isn't registered in mtwilson we can't get the hardware uuid so we have to reject the request
        if( !UUID.isValid(subject)) {
            String subjectUuid = findSubjectHardwareUuid(subject);
            if (subjectUuid == null) {
                log.error("Cannot find hardware uuid for subject: {}", subject);
                throw new IllegalArgumentException("Invalid subject specified in the call");
            }
            subject = subjectUuid;
        }
        if( selections == null ) {
            log.error("Selection input is null");
            throw new IllegalArgumentException("Invalid selections specified.");
        }
        // if external ca is configured then we only save the request to the database and indicate async processing in our response
//        if( configuration.isTagProvisionExternal() || isAsync(request) ) {
//            // requires async processing - we store the request, and an external ca will poll for requests, generate certs, and post the certs back to us; the client can periodically check the status and then download the cert when it's available
//            storeAsyncRequest(subject, selections, response);
//            return null;
//        }
        // if always-generate/no-cache (cache mode off) is enabled then generate it right now and return it - no need to check database for existing certs etc. 
        String cacheMode = "on";
        if( selections.getOptions() != null && selections.getOptions().getCache() != null && selections.getOptions().getCache().getMode() != null ) {
            cacheMode = selections.getOptions().getCache().getMode().value();
        }
        
        // first figure out which selection will be used for the given subject - also filters selections to ones that are currently valid or not marked with validity period
        SelectionType targetSelection = ca.findCurrentSelectionForSubject(UUID.valueOf(subject), selections); // throws exception if there is no matching selection and no matching default selection
        
        log.debug("Cache mode {}", cacheMode);
        if( "off".equals(cacheMode) && targetSelection != null ) {
            byte[] certificateBytes = ca.createTagCertificate(UUID.valueOf(subject), targetSelection);
            Certificate certificate = storeTagCertificate(subject, certificateBytes);
            return certificate;
        }
        
        // if there is an existing currently valid certificate we return it
        CertificateFilterCriteria criteria = new CertificateFilterCriteria();
        criteria.subjectEqualTo = subject;
        criteria.revoked = false;
        criteria.validOn = new Iso8601Date(new Date()); 
        CertificateCollection results = certificateRepository.search(criteria);
        Date today = new Date();
        Certificate latestCert = null;
        BigInteger latestCreateTime = BigInteger.ZERO;
        //  pick the most recently created cert that is currently valid and has the same attributes specified in the selection.  we evaluate the notBefore and notAfter fields of the certificate itself even though we already narrowed the search to currently valid certs using the search criteria. 
        if( !results.getCertificates().isEmpty() ) {
            for (Certificate certificate : results.getCertificates()) {
                X509AttributeCertificate attributeCertificate = X509AttributeCertificate.valueOf(certificate.getCertificate());
                if (today.before(attributeCertificate.getNotBefore())) {
                    continue;
                }
                if (today.after(attributeCertificate.getNotAfter())) {
                    continue;
                }
                if( targetSelection != null && !certificateAttributesEqual(attributeCertificate, targetSelection)) {
                    continue;
                }
                // While creating the certificates we are storing the create time in the serial number field
                // And here we want to return the latest certificate so we keep track as we look through the results.
                if (latestCreateTime.compareTo(attributeCertificate.getSerialNumber()) <= 0) {
                    latestCreateTime = attributeCertificate.getSerialNumber();
                    latestCert = certificate;
                }
            }
        }
        // Check if a valid certificate was found during the search.
        if (latestCert != null) {
            X509AttributeCertificate attributeCertificate = X509AttributeCertificate.valueOf(latestCert.getCertificate());
            AssetTagCertAssociateRequest atca = new AssetTagCertAssociateRequest();
            atca.setSha1OfAssetCert(Sha1Digest.digestOf(attributeCertificate.getEncoded()).toByteArray());
            AssetTagCertBO object = new AssetTagCertBO();
              try {                  
                  object.mapAssetTagCertToHost(atca);
              } catch (CryptographyException ex) {
                  java.util.logging.Logger.getLogger(ProvisionTagCertificate.class.getName()).log(Level.SEVERE, null, ex);
              }
//            ca.mapTagCertificate(UUID.valueOf(subject), attributeCertificate.);
            return latestCert;
        }
        
        // no cached certificate so generate a new certificate
        if( targetSelection == null ) {
            throw new IllegalArgumentException("No cached certificate and no default selection provided");
        }
        byte[] certificateBytes = ca.createTagCertificate(UUID.valueOf(subject), targetSelection);
        Certificate certificate = storeTagCertificate(subject, certificateBytes);
        return certificate;
        
    }
//    
//    /**
//     * Check that the attributes in the certificate are the same as the attributes in the given selection.
//     * The order is not considered so they do not have to be in the same order.
//     * 
//     * The given selection must have inline attributes (not requiring any lookup by id or name).
//     * 
//     * @return true if the attribute certificate has exactly the same attributes as in the given selection
//     */
    protected boolean certificateAttributesEqual(X509AttributeCertificate certificate, SelectionType selection) throws IOException {
        List<Attribute> certAttributes = certificate.getAttribute();
        boolean certAttrMatch[] = new boolean[certAttributes.size()]; // initialized with all false, later we mark individual elements true if they are found within the given selection, so that if any are left false at the end we know that there are attributes in the cert that were not in the selection
        // for every attribute in the selection, check if it's present in the certificate 
        for (AttributeType xmlAttribute:  selection.getAttribute()) {
            X509AttrBuilder.Attribute oidAndValue = Util.toAttributeOidValue(xmlAttribute);
            // look through the certificate for same oid and value
            boolean found = false;
            for(int i=0; i<certAttrMatch.length; i++) {
                if( Arrays.equals(certAttributes.get(i).getAttrType().getDEREncoded(), oidAndValue.oid.getDEREncoded()) ) {
                    if( Arrays.equals(certAttributes.get(i).getAttributeValues()[0].getDEREncoded(), oidAndValue.value.getDEREncoded()) ) {
                        certAttrMatch[i] = true;
                        found = true;
                    }
                }
            }
            if( !found ) {
                log.debug("Certificate does not have attribute oid {} and value {}", Hex.encodeHexString(oidAndValue.oid.getDEREncoded()), Hex.encodeHexString(oidAndValue.value.getDEREncoded()));
                return false;
            }
        }
        // check if the certificate has any attributes that are not in the selection 
        for(int i=0; i<certAttrMatch.length; i++) {
            if( !certAttrMatch[i] ) {
                log.debug("Selection does not have attribute oid {} and value {}", Hex.encodeHexString(certAttributes.get(i).getAttrType().getDEREncoded()), Hex.encodeHexString(certAttributes.get(i).getAttributeValues()[0].getDEREncoded()));
                return false;
            }
        }
        return true; // certificate and selection have same set of attribute (oid,value) pairs
    }
    
    /**
     * Because the selection xml format does not
     * include the target host's subject uuid, the client must specify
     * the target host subject uuid either with an HTTP header "Subject" whose
     * value is the uuid, or with a query parameter "subject" whose value is
     * the uuid.  If both are present only the HTTP header is used. If neither
     * is present the server will return a bad request error.
     * 
     * Unlike the JSON API, this method does not return the original request
     * as the response because the clients that send XML or encrypted XML
     * don't need it echoed back to them. If there is a response then it is
     * the generated tag certificate. If there is no response and the 
     * Asynchronous header is set to "true" in the response it means the
     * certificate will be generated later; Link headers in the same response
     * will indicate where the generated certificate can be obtained once
     * it is available.
     * 
     * @param locator
     * @param message
     * @param request 
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(CryptoMediaType.APPLICATION_PKIX_CERT)
    //@RequiresPermissions("tag_certificates:create")         
    public byte[] createOneFromJsonToBytes(@InjectParam CertificateRequestLocator locator, String json, @Context HttpServletRequest request, @Context HttpServletResponse response) 
            throws IOException, ApiException, SignatureException, SQLException, CertificateException  {
        Certificate certificate = createOneJson(locator, json, request, response);
        if (certificate != null)
            return certificate.getCertificate();
        else {
            log.error("Error creating the certificate.");
            throw new CertificateException("Error creating the certificate.");
        }
    }
    
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
//    @RequiresPermissions("tag_certificates:create")         
    public Certificate createOneJson(@InjectParam CertificateRequestLocator locator, String json, @Context HttpServletRequest request, @Context HttpServletResponse response) 
            throws IOException, ApiException, SignatureException, SQLException, IllegalArgumentException, com.intel.mtwilson.ApiException {        
        SelectionsType selections = null;
        if( json != null ) {
            selections = Util.fromJson(json);
        }
        return createOne(getSubject(request, locator), selections, request, response);
    }
//    
    /**
     * Because the selection xml format does not
     * include the target host's subject uuid, the client must specify
     * the target host subject uuid either with an HTTP header "Subject" whose
     * value is the uuid, or with a query parameter "subject" whose value is
     * the uuid.  If both are present only the HTTP header is used. If neither
     * is present the server will return a bad request error.
     * 
     * Unlike the JSON API, this method does not return the original request
     * as the response because the clients that send XML or encrypted XML
     * don't need it echoed back to them.
     * 
     * @param locator
     * @param message
     * @param request 
     */
    @POST
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(CryptoMediaType.APPLICATION_PKIX_CERT)
    //@RequiresPermissions("tag_certificates:create")         
    public byte[] createOneFromXmlToBytes(@InjectParam CertificateRequestLocator locator, String xml, @Context HttpServletRequest request, @Context HttpServletResponse response) 
            throws IOException, ApiException, SignatureException, SQLException, CertificateException {
        Certificate certificate = createOneXml(locator, xml, request, response);
        if (certificate != null)
            return certificate.getCertificate();
        else {
            log.error("Error creating the certificate.");
            throw new CertificateException("Error creating the certificate.");
        }
    }
    
    @POST
    @Consumes(MediaType.APPLICATION_XML)
    @Produces(MediaType.APPLICATION_XML)
    //@RequiresPermissions("tag_certificates:create")         
    public Certificate createOneXml(@InjectParam CertificateRequestLocator locator, String xml, @Context HttpServletRequest request, @Context HttpServletResponse response) 
            throws IOException, ApiException, SignatureException, SQLException, IllegalArgumentException, com.intel.mtwilson.ApiException  {
         //TagConfiguration configuration = new TagConfiguration(My.configuration().getConfiguration());
        //TagConfiguration configuration = new TagConfiguration(ASConfig.getConfiguration()); //Variable never used
        SelectionsType selections = null;
        if( xml != null ) {
            selections = Util.fromXml(xml);
        }
        return createOne(getSubject(request, locator), selections, request, response);
    }
    
    
    private String getSubject(HttpServletRequest request, CertificateRequestLocator locator) {
        String subject = request.getHeader("Subject");
        if( subject != null && !subject.isEmpty()) {
            return subject; 
        }
        else if( locator.subject != null && !locator.subject.isEmpty() ) {
            return locator.subject; // from query paramter  ?subject={subject}            
        }
        else {
            throw new WebApplicationException(Response.Status.BAD_REQUEST); 
        }
    }
    
    /**
     * Looks up hardware uuid of host in mtwilson; host already be registered.
     *
     * @param ip address or hostname
     * @return
     */
    public String findSubjectHardwareUuid(String ip) throws IOException, ApiException, SignatureException, com.intel.mtwilson.ApiException {
        log.debug("Querying host {} in Mt Wilson", ip);
        List<TxtHostRecord> hostList = Global.mtwilson().queryForHosts(ip, true);
        if (hostList == null || hostList.isEmpty()) {
            log.debug("host uuid lookup didn't return back any results");
            //throw new ASException(new Exception("No host records found, please verify your host is in mtwilson or provide a hardware uuid in the subject field.")); // 
            log.warn("No host records found for {}, please verify your host is in mtwilson or provide a hardware uuid in the subject field", ip);
            return null;
        }
        log.debug("get host uuid returned " + hostList.get(0).Hardware_Uuid);
        return hostList.get(0).Hardware_Uuid;

    }
    
    
    
        
}
