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
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Supports standard, compact, and mixed notations.
 * 
 * Standard notation: eight 16-bit words using hex notation, delimited by colons, leading zeros optional
 *    Example: FA47:0:0:0:0:D39:1:5CA2
 * 
 * Compact: 
 * 
 * Mixed: IPv6 and IPv4 notation together. Usually when IPv6 is an extension of an IPv4 space.
 *    Example: FA47:0:0:0:0:D39:10.0.92.21
 * 
 * TODO: regexp for compact notation and compact-mixed notation;  see the Regular Expressions Cookbook.
 * 
 * @author jbuhacoff
 */
public class IPv6Address extends ObjectModel {
    private static final String rDecimalByte = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
    private static final String rIPv4 = "(?:"+rDecimalByte+"\\.){3}"+rDecimalByte;
    private static final String rStandardWord = "[A-F0-9]{1,4}";
    private static final String rStandardNotation = "^(?:"+rStandardWord+":){7}"+rStandardWord+"$";
    private static final Pattern pStandardNotation = Pattern.compile(rStandardNotation);
    private static final String rMixedNotation = "^(?:"+rStandardWord+":){6}"+rIPv4+"$";
    private static final Pattern pMixedNotation = Pattern.compile(rMixedNotation);
//    private static final String rCompactWord = "[A-F0-9]{0,4}";
//    private static final String rCompactNotation7 = "^(?:"+rCompactWord+":){0,7}"+rCompactWord+"$";
//    private static final String rCompactNotation8 = "^(?:"+rStandardWord+":){7}:|:(?::"+rStandardWord+"){7}$";
    
    private String input;
    private transient Notation notation = null;
    
    public IPv6Address(String text) {
        input = text.trim();
    }
    
    @Override
    protected void validate() {
        Matcher mStandard = pStandardNotation.matcher(input);
        if( mStandard.matches() ) {
            notation = Notation.STANDARD;
            return;
        }
        Matcher mMixed = pMixedNotation.matcher(input);
        if( mMixed.matches() ) {
            notation = Notation.MIXED;
            return;
        }
        // TODO: compact and compact-mixed
        fault("Unrecognized IPv6 format: %s", input);
    }
    
    @Override
    public String toString() { return input; }
    
    public Notation notation() { return isValid() ? notation : null; }

    public byte[] toByteArray() { 
        if( !isValid() ) { return null; }
        try {
            return Inet6Address.getByName(input).getAddress(); // XXX is this ok or is there another way?
        }
        catch(UnknownHostException e) {
            return null;
        }
    }
    
    public static enum Notation { STANDARD, MIXED; } // TODO: COMPACT, COMPACT_MIXED
}
