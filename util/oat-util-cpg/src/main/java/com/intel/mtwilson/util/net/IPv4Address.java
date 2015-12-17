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

package com.intel.mtwilson.util.net;

import com.intel.mtwilson.util.validation.ObjectModel;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Supports standard decimal notation for IPv4 such as 192.168.0.1
 * 
 * This class represents the address for a single host. 
 * Intentionally does not support subnet/CIDR notation. That belongs in a NetworkAddress class.
 * 
 * @author jbuhacoff
 */
public class IPv4Address extends ObjectModel {
    private static final String rDecimalByte = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
    private static final String rIPv4 = "(?:"+rDecimalByte+"\\.){3}"+rDecimalByte;
    private static final Pattern pIPv4 = Pattern.compile(rIPv4);
    
    private String input;
    
    public IPv4Address(String text) {
        input = text.trim();
    }
    
    @Override
    protected void validate() {
        Matcher mIPv4 = pIPv4.matcher(input);
        if( mIPv4.matches() ) {
            return;
        }
        fault("Unrecognized IPv4 format: %s", input);
    }
    
    @Override
    public String toString() { return input; }
    
    public byte[] toByteArray() { 
        if( !isValid() ) { return null; }
        try {
            return Inet4Address.getByName(input).getAddress(); // XXX is this ok or is there another way?
        }
        catch(UnknownHostException e) {
            return null;
        }
    }
}
