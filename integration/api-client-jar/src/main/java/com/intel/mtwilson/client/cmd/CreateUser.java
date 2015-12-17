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

import com.intel.mtwilson.client.AbstractCommand;
import com.intel.mtwilson.crypto.RsaUtil;
import com.intel.mtwilson.util.crypto.SimpleKeystore;
import com.intel.mtwilson.io.Filename;
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
public class CreateUser extends AbstractCommand {

    @Override
    public void execute(String[] args) throws Exception {
            // args[1] should be path to folder
            File directory = new File(args[0]);
            String username = null, password = null;
            // args[2] is optional username (if not provided we will prompt)
            if( args.length > 1 ) { username = args[1]; }
            // args[3] is optional password plaintext (not recommended) or environment variable name (recommended) (if not provided we will prompt)
            if( args.length > 2 ) { password = args[2]; }
            
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            if( username == null || username.isEmpty() ) {
                System.out.print("Username: ");
                username = in.readLine();
            }
            if( password == null || password.isEmpty() ) {
                System.out.print("Password: ");
                password = in.readLine();
                System.out.print("Password again: ");
                String passwordAgain = in.readLine();
                if( !password.equals(passwordAgain) ) {
                    System.err.println("The two passwords don't match");
                    System.exit(1);
                }
            }
            else if( password.startsWith("env:") && password.length() > 4 ) {
                String varName = password.substring(4);
                password = System.getenv(varName);
            }

            if( password == null || password.isEmpty() || password.length() < 6 ) {
                System.err.println("The password must be at least six characters");
                System.exit(1);
            }
            String subject = username; //String.format("CN=%s", username);
            
            File keystoreFile = new File(directory.getAbsoluteFile() + File.separator + Filename.encode(username) + ".jks");
            SimpleKeystore keystore = new SimpleKeystore(keystoreFile, password);
            KeyPair keypair = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE);
            X509Certificate certificate = RsaUtil.generateX509Certificate(subject, keypair, RsaUtil.DEFAULT_RSA_KEY_EXPIRES_DAYS);
            keystore.addKeyPairX509(keypair.getPrivate(), certificate, username, password);
            keystore.save();
            System.out.println("Created keystore: "+keystoreFile.getName());
    }

}
