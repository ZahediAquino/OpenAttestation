/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.tag.rest.resource;

import com.intel.mtwilson.datatypes.KvAttribute;
import com.intel.mtwilson.datatypes.KvAttributeCollection;
import com.intel.mtwilson.datatypes.KvAttributeFilterCriteria;
import com.intel.mtwilson.datatypes.KvAttributeLocator;
import com.intel.mtwilson.datatypes.NoLinks;
import com.intel.mtwilson.datatypes.AbstractJsonapiResource;
//import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.tag.repository.KvAttributeRepository;
import javax.ws.rs.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ssbangal
 */
//@V2
@Path("/tag-kv-attributes")
public class KvAttributes extends AbstractJsonapiResource<KvAttribute, KvAttributeCollection, KvAttributeFilterCriteria, NoLinks<KvAttribute>, KvAttributeLocator> {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KvAttributes.class);

    private KvAttributeRepository repository;
    
    public KvAttributes() {
        repository = new KvAttributeRepository();
    }
    
    @Override
    protected KvAttributeCollection createEmptyCollection() {
        return new KvAttributeCollection();
    }

    @Override
    protected KvAttributeRepository getRepository() {
        return repository;
    }
        
}
