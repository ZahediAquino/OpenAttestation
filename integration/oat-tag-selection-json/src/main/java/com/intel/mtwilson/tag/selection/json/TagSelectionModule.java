/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.tag.selection.json;

import org.codehaus.jackson.Version;
//import com.fasterxml.jackson.core.Version;
import org.codehaus.jackson.map.Module;
import com.intel.mtwilson.tag.selection.xml.AttributeType;
import com.intel.mtwilson.tag.selection.xml.CacheModeAttribute;
import com.intel.mtwilson.tag.selection.xml.DefaultType;
import com.intel.mtwilson.tag.selection.xml.SelectionType;
import com.intel.mtwilson.tag.selection.xml.SelectionsType;
import com.intel.mtwilson.tag.selection.xml.TextAttributeType;

/**
 *
 * @author jbuhacoff
 */
public class TagSelectionModule extends Module {

    @Override
    public String getModuleName() {
        return "TagSelectionModule";
    }

    @Override
    public Version version() {
        return new Version(1,0,0,"com.intel.mtwilson.integration");
//        return new Version(1,0,0,"com.intel.mtwilson.integration","mtwilson-tag-selection-json",null);
    }

    @Override
    public void setupModule(SetupContext sc) {
        sc.setMixInAnnotations(CacheModeAttribute.class, CacheModeAttributeMixIn.class);
        sc.setMixInAnnotations(SelectionsType.class, SelectionsTypeMixIn.class);
        sc.setMixInAnnotations(DefaultType.class, DefaultTypeMixIn.class);
        sc.setMixInAnnotations(SelectionType.class, SelectionTypeMixIn.class);
        sc.setMixInAnnotations(AttributeType.class, AttributeTypeMixIn.class);
        sc.setMixInAnnotations(TextAttributeType.class, TextAttributeTypeMixIn.class);
//        sc.appendAnnotationIntrospector(new JaxbAnnotationIntrospector(sc.getTypeFactory())); // still get <attribute><text><value>Country=US</value></text><oid>2.5.4.789.1</oid></attribute>  with oid as a child tag of attribute instead of as a... attribute of attribute.
//        sc.insertAnnotationIntrospector(new JaxbAnnotationIntrospector(sc.getTypeFactory())); // still get <attributes><text><value>Country=US</value></text><oid>2.5.4.789.1</oid></attributes>
    }
    
}
