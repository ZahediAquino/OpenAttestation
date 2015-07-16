/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.datatypes;

import java.util.Properties;
//import com.intel.mtwilson.datatypes.Configuration;
import com.intel.mtwilson.tls.TlsConnection;
import java.net.URL;

/**
 *
 * @author jbuhacoff
 */
public class MtWilsonClient extends JaxrsClient {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MtWilsonClient.class);
    
    public MtWilsonClient(URL url) throws Exception {
        super(JaxrsClientBuilder.factory().url(url).build());
    }

    public MtWilsonClient(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public MtWilsonClient(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    public MtWilsonClient(Properties properties, TlsConnection tlsConnection) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).tlsConnection(tlsConnection).build());
    }

}
