/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.datatypes;

import com.intel.mtwilson.util.crypto.SimpleKeystore;
import com.intel.mtwilson.util.io.Resource;
import com.intel.mtwilson.tls.TlsPolicy;
import java.net.URL;
/**
 * 
 * To register your factory implementation, create the file
 * META-INF/services/com.intel.mtwilson.api.ClientFactory and set its contents like this:
# My Client Factory Implementation:
com.intel.my.app.MyClientFactory
 * 
 *
 * @author jbuhacoff
 */
public interface ClientFactorySpi {
//    MtWilson createClientFor(URL webserviceUrl); 

    SimpleKeystore createUserInResource(Resource keystoreDir, String keystoreUsername, String keystorePassword, URL wsUrl, TlsPolicy tlsPolicy, String[] roles);
    MtWilson clientForUserInResource(Resource keystoreDir, String keystoreUsername, String keystorePassword, URL wsUrl, TlsPolicy tlsPolicy);

}
