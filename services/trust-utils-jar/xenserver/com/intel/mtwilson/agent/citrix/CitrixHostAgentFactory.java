//CitrixHostAgentFactory
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/* */
package com.intel.mtwilson.agent.citrix;

import com.intel.mtwilson.agent.HostAgent;
import com.intel.mtwilson.agent.VendorHostAgentFactory;
import com.intel.mtwilson.util.net.InternetAddress;
import com.intel.mtwilson.tls.TlsConnection;
import com.intel.mtwilson.tls.TlsPolicy;
import java.io.IOException;
import java.net.URL;
/* */
/**
 *
 * @author stdalex
 */
/* */
public class CitrixHostAgentFactory implements VendorHostAgentFactory {
    @Override
    public HostAgent getHostAgent(InternetAddress hostAddress, String vendorConnectionString, TlsPolicy tlsPolicy) throws IOException {
        CitrixClient client = new CitrixClient(new TlsConnection(vendorConnectionString, tlsPolicy));
        client.init();
        return new CitrixHostAgent(client);
    }
}
/* */

