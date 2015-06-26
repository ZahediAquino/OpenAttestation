/*
 * Copyright (c) 2013, Intel Corporation. 
 * All rights reserved.
 * 
 * The contents of this file are released under the BSD license, you may not use this file except in compliance with the License.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of Intel Corporation nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.intel.mtwilson.agent;

import com.intel.mtwilson.datatypes.InternetAddress;
import com.intel.mtwilson.tls.TlsPolicy;
import java.io.IOException;

/**
 *
 * @author jbuhacoff
 */
public interface VendorHostAgentFactory {
    /**
     * On success, a HostAgent object should be returned for the specified hostAddress
     * which is able to obtain information about the host.
     * 
     * If the vendor-specific factory uses a connection pool to maintain connections
     * to its servers, the connection pool should be keyed by the server AND by the
     * TLS Policy provided by the caller. A connection should only be reused if one
     * exists for that server with the specified TLS Policy.  If Creates or reuses a vmware client connection to the vcenter from the
     * connection pool. In order to reuse a connection both the connection string
     * and the tlspolicy must be the same. If the connection string matches a
     * connection in the pool but the tlspolicy is different, a new connection
     * will be created with the given tlspolicy.
     * 
     * @param hostAddress the IP Address or Hostname of the Intel TXT-enabled host for which the caller wants a HostAgent instance
     * @param vendorConnectionString a vendor-specific URL or other string that specifies how to connect to the host
     * @param tlsPolicy the TLS Policy for the connection, specifying what are trusted certificates and whether or which self-signed certificates are accepted, etc.
     * @return 
     */
    HostAgent getHostAgent(InternetAddress hostAddress, String vendorConnectionString, TlsPolicy tlsPolicy) throws IOException;
}
