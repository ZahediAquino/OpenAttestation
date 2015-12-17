/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.tag.rest.rpc;

//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.util.io.UUID;
import com.intel.mtwilson.datatypes.AssetTagCertRevokeRequest;
import com.intel.mtwilson.launcher.ws.ext.RPC;
import com.intel.mtwilson.tag.repository.RepositoryException;
import com.intel.mtwilson.tag.repository.RepositoryInvalidInputException;
import com.intel.mtwilson.tag.common.Global;
import com.intel.mtwilson.tag.dao.TagJdbi;
import com.intel.mtwilson.tag.dao.jdbi.CertificateDAO;
import com.intel.mtwilson.datatypes.Certificate;
import com.intel.mtwilson.datatypes.CertificateLocator;
import com.intel.mtwilson.datatypes.CertificateRequestLocator;
import com.intel.mtwilson.io.ConfigurationUtil;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import com.sun.jersey.api.core.InjectParam;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;


/**
 * This would be called from the "revoke" link next to each certificate in the
 * UI.
 * 
 * @author ssbangal
 */
@Path("/tag-certificate-requests-rpc/revoke-tag-certificate")
@RPC("revoke-tag-certificate")
//@JacksonXmlRootElement(localName="revoke_tag_certificate")
public class RevokeTagCertificate{
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(RevokeTagCertificate.class);

       
    private UUID certificateId;

    public UUID getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(UUID certificateId) {
        this.certificateId = certificateId;
    }
       
    @POST
//    @Override
    //@RequiresPermissions("tag_certificates:delete")         
    public void revokeCert(@QueryParam("certId")String certId) {
        log.debug("RPC: RevokeTagCertificate - Got request to revocation of certificate: {}",certId);
        setCertificateId(UUID.valueOf(certId));
        try (CertificateDAO dao = TagJdbi.certificateDao()) {
            CertificateLocator locator = new CertificateLocator();
            locator.id = certificateId;
            
            Certificate obj = dao.findById(certificateId);
            if (obj != null) 
            {
                org.apache.commons.configuration.Configuration conf = ConfigurationUtil.getConfiguration(); // tries jvm properties, environment variables, then mtwilson.properties;  you can set location of mtwilson.properties with -Dmtwilson.home=/path/to/dir
                ApiClient mtwilson = new ApiClient(conf);
                log.debug("RPC: RevokeTagCertificate - Sha1 of the certificate about to be revoked is {}.", obj.getSha1());
                dao.updateRevoked(certificateId, true);                
                AssetTagCertRevokeRequest request = new AssetTagCertRevokeRequest();
                request.setSha1OfAssetCert(obj.getSha1().toByteArray());
                mtwilson.revokeAssetTagCertificate(request);
                //Global.mtwilson().revokeAssetTagCertificate(request);
                log.info("RPC: RevokeTagCertificate - Certificate with id {} has been revoked successfully.");
            } else {
                log.error("RPC: RevokeTagCertificate - Certificate with id {} does not exist.", certificateId);
                throw new RepositoryInvalidInputException(locator);
            }

        } catch (RepositoryException re) {
            throw re;            
        } catch (Exception ex) {
            log.error("RPC: RevokeTagCertificate - Error during certificate revocation.", ex);
            throw new RepositoryException(ex);
        } 
        
    }
    
}
