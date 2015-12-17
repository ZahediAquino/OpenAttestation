/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.tag.selection.json;

//import com.fasterxml.jackson.annotation.JsonInclude;

import org.codehaus.jackson.map.annotate.JsonSerialize;


/**
 *
 * @author jbuhacoff
 */
//@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
public abstract class TextAttributeTypeMixIn {
}
