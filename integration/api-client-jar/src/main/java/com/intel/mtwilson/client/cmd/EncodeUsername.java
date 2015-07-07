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

package com.intel.mtwilson.client.cmd;

import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.client.AbstractCommand;
import com.intel.mtwilson.datatypes.HostTrustResponse;
import com.intel.mtwilson.util.net.Hostname;
import com.intel.mtwilson.io.Filename;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 *     HostTrustResponse getHostTrust(Hostname hostname) throws IOException, ApiException, SignatureException;
 * 
 * @author jbuhacoff
 */
public class EncodeUsername extends AbstractCommand {

    @Override
    public void execute(String[] args) throws Exception {
        if( args.length < 1 ) {
            throw new IllegalArgumentException("Usage: EncodeUsername alias | EncodeUsername -  (and supply username on stdin)");
        }
        if( args[0].equals("-") ) {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            System.out.println(Filename.encode(in.readLine()));
            in.close();
        }
        else {
            System.out.println(Filename.encode(args[0])); // XXX doesn't work.  "hello world" becomes "hello" instead of "hello%xxworld"
        }
    }

}
