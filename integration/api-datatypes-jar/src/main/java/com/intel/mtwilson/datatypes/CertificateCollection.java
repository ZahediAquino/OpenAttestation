/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.datatypes;

//import com.fasterxml.jackson.annotation.JsonInclude;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlElementWrapper;
//import javax.xml.bind.annotation.XmlType;
//import com.fasterxml.jackson.databind.annotation.JsonSerialize;
//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
//import com.intel.mtwilson.datatypes.DocumentCollection;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author ssbangal
 */
//@JacksonXmlRootElement(localName="certificate_collection")
@XmlRootElement(name = "certificate_collection")
public class CertificateCollection extends DocumentCollection<Certificate>{

    private final ArrayList<Certificate> certificates = new ArrayList<Certificate>();
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CertificateCollection.class);
    
    @JsonSerialize(include=JsonSerialize.Inclusion.ALWAYS) // jackson 1.9
    @XmlElementWrapper(name="certificates")
    
//    @JsonInclude(JsonInclude.Include.ALWAYS)                // jackson 2.0
//    @JacksonXmlElementWrapper(localName="certificates")
//    @JacksonXmlProperty(localName="certificate")    
    
    public List<Certificate> getCertificates() { 
        log.info("getCertificates()");
        return certificates; 
    }

    @Override
    public List<Certificate> getDocuments() {
        log.info("getDocuments()");
        return getCertificates();
    }
    
}
