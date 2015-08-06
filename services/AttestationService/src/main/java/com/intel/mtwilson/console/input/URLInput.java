/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.console.input;

import com.intel.mtwilson.util.validation.InputModel;
import java.net.MalformedURLException;
import java.net.URL;

/**
 *
 * @author jbuhacoff
 */
public class URLInput extends InputModel<URL> {

    @Override
    protected URL convert(String input) {
        try {
            URL url = new URL(input);
            return url;
        }
        catch(MalformedURLException e) {
            fault(e, "Invalid URL: %s", input);
        }
        return null;
    }
    

}
