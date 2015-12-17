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
import com.intel.mtwilson.crypto.RsaUtil;
import com.intel.mtwilson.util.crypto.SimpleKeystore;
import com.intel.mtwilson.datatypes.HostTrustResponse;
import com.intel.mtwilson.util.net.Hostname;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 *     HostTrustResponse getHostTrust(Hostname hostname) throws IOException, ApiException, SignatureException;
 * 
 * @author jbuhacoff
 */
public class CreateSSLCertificate extends AbstractCommand {

    @Override
    public void execute(String[] args) throws Exception {
        if( args.length < 5 ) {
            throw new IllegalArgumentException("Usage: CreateSSLCertificate \"192.168.1.100\" \"ip:192.168.1.100\" /path/to/keystore.jks alias [env:password_var]");
        }
        String subject = args[0];
        String alternateName = args[1];
        File keystoreFile = new File(args[2]);
        String alias = args[3];
        String password = args[4];
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        if( password == null || password.isEmpty() ) {
            System.out.print("Password: ");
            password = in.readLine();
            System.out.print("Password again: ");
            String passwordAgain = in.readLine();
            if( !password.equals(passwordAgain) ) {
                throw new IllegalArgumentException("The two passwords don't match");
            }
        }
        else if( password.startsWith("env:") && password.length() > 4 ) {
            String varName = password.substring(4);
            password = System.getenv(varName);
        }

        SimpleKeystore keystore = new SimpleKeystore(keystoreFile, password);
        KeyPair keypair = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE);
        X509Certificate certificate = RsaUtil.generateX509Certificate(subject, alternateName, keypair, RsaUtil.DEFAULT_RSA_KEY_EXPIRES_DAYS);
        keystore.addKeyPairX509(keypair.getPrivate(), certificate, alias, password);
        keystore.save();
    }

}
