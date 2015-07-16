/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.tag.selection.json;

import org.codehaus.jackson.annotate.JsonProperty;
import com.intel.mtwilson.tag.selection.xml.SelectionType;
import java.util.List;
import org.codehaus.jackson.map.annotate.JsonSerialize;

/**
 * The commented out block applies only to xml serialization; currently
 * only json serialization is used.
 *
 * @author jbuhacoff
 */
public abstract class SelectionsTypeMixIn {

    @JsonProperty("selections")
    @JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
//    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    /*
    @JacksonXmlElementWrapper(localName="selections")
    @JacksonXmlProperty(localName="selection")
    */
    protected List<SelectionType> selection;
    
    // if the mix-in includes both the protected selections variable and this getter, the JsonProperty annotation must be applied to both or else we get java.lang.IllegalStateException: Conflicting property name definitions: 'selection' (for [field com.intel.mtwilson.tag.selection.xml.SelectionsType#selection]) vs 'selections' (for [method com.intel.mtwilson.tag.selection.xml.SelectionsType#getSelection(0 params)])
//    @JsonProperty("selections")
//    @JsonInclude(JsonInclude.Include.NON_EMPTY)
//    abstract List<SelectionType> getSelection();
}
