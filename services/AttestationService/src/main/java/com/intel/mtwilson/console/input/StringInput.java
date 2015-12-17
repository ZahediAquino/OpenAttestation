/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.console.input;

import com.intel.mtwilson.util.validation.InputModel;

/**
 *
 * @author jbuhacoff
 */
public class StringInput extends InputModel<String> {

    @Override
    protected String convert(String input) {
        return input;
    }
    

}
