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

package com.intel.mtwilson.agent.intel;

import com.intel.mountwilson.as.helper.TrustAgentSecureClient;
import com.intel.mtwilson.tls.TlsConnection;
import org.apache.commons.pool.BaseKeyedPoolableObjectFactory;

/**
 * The IntelClientFactory creates TrustAgentSecureClient instances. The 
 * TrustAgentSecureClient does not have a connect() or disconnect() method.
 * It creates a new connection for every call. This may be changed in a
 * future release.
 * 
 * See also KeyedPoolableObjectFactory in Apache Commons Pool
 * 
 * @author jbuhacoff
 */
public class IntelClientFactory extends BaseKeyedPoolableObjectFactory<TlsConnection,TrustAgentSecureClient> {
    
    @Override
    public TrustAgentSecureClient makeObject(TlsConnection tlsConnection) throws Exception {
        TrustAgentSecureClient client = new TrustAgentSecureClient(tlsConnection); // client has to parse the string to get ip address and port for trust agent. 
        return client;
    }
    
    /**
     * This gets called every time an object is being borrowed from the pool.
     * We don't need to do anything here, as vmware clients in the pool should
     * already be connected (that is the purpose of maintaining a pool of vmware
     * clients).
     * @param tlsConnection
     * @param client
     * @throws Exception 
     */
    @Override
    public void activateObject(TlsConnection tlsConnection, TrustAgentSecureClient client) throws Exception {
    }
    
    /**
     * If the pool is configured to validate objects before borrowing, then
     * this is called every time an object is being borrowed from the pool.
     * We validate the vmware client connection by making a quick
     * call to vcenter here. that way if it fails the pool can destroy the 
     * client and create a new one for the caller.
     * @param tlsConnection
     * @param client
     * @return 
     */
    @Override
    public boolean validateObject(TlsConnection tlsConnection, TrustAgentSecureClient client) {
//        return client.isConnected(); 
        return true; // XXX TODO is there a way to validate the trust agent client connection? maybe try sending a request for host info? or something else lightweight, with a really small timeout
    }
    
    /**
     * This is called when the pool needs to get rid of a client - maybe because
     * it was idle too long and lost its connection, or because there are too
     * many idle clients, etc.
     * @param tlsConnection
     * @param client
     * @throws Exception 
     */
    @Override
    public void destroyObject(TlsConnection tlsConnection, TrustAgentSecureClient client) throws Exception {
//        client.disconnect();
    }
}
