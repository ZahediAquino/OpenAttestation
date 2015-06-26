/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.tag.rest.resource;

import com.intel.mtwilson.datatypes.Certificate;
import com.intel.mtwilson.datatypes.CertificateCollection;
import com.intel.mtwilson.datatypes.CertificateFilterCriteria;
import com.intel.mtwilson.datatypes.CertificateLocator;
import com.intel.mtwilson.datatypes.NoLinks;
import com.intel.mtwilson.datatypes.AbstractCertificateJsonapiResource;
//import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.tag.rest.repository.CertificateRepository;
import javax.ws.rs.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ssbangal
 */
//@V2
@Path("/tag-certificates")
public class Certificates extends AbstractCertificateJsonapiResource<Certificate, CertificateCollection, CertificateFilterCriteria, NoLinks<Certificate>, CertificateLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Certificates.class);

    private CertificateRepository repository;
    
    public Certificates() {
        repository = new CertificateRepository();
    }
    
    @Override
    protected CertificateCollection createEmptyCollection() {
        return new CertificateCollection();
    }

    @Override
    protected CertificateRepository getRepository() {
        return repository;
    }
        
}
