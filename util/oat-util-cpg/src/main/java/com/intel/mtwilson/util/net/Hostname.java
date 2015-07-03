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

import com.intel.mtwilson.validation.Fault;
import com.intel.mtwilson.validation.Model;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.codehaus.jackson.annotate.JsonValue;

/**
 * Representation of a hostname. This class enforces some rules on the 
 * syntax of the hostname to make it usable without further type checking.
 * 
 * A Hostname can also contain an IP address value, even though the model
 * objects are not currently related in any way. 
 * 
 * TODO relate the Hostname and IPAddress models in some way, possibly with
 * an aggregated type or union, something that can be a HostnameOrIpAddress.
 * 
 * XXX TODO need to rewrite as extension to ObjectModel
 * 
 * @since 0.5.1
 * @author jbuhacoff
 */
public class Hostname implements Model {

    private String hostname = null;

    /*
    private Hostname() {
    }
    *
    */

    public Hostname(String hostname) {
        setHostname(hostname);
    }


    public final void setHostname(String hostname) {
        if( hostname == null ) { throw new IllegalArgumentException("Missing hostname"); } // or NullPointerException
        if( hostname.isEmpty() ) { throw new IllegalArgumentException("Hostname is empty"); } // or IllegalArgumentException
        if (isValid(hostname)) {
            this.hostname = hostname;
        } else {
            throw new IllegalArgumentException("Invalid hostname: " + hostname);
        }
    }

    public final String getHostname() {
         return hostname;
    }

    /**
     * Returns the hostname so that you can easily concatenate to a string.
     * Example: assert new Hostname("1.2.3.4").toString().equals("1.2.3.4");
     *
     * @see java.lang.Object#toString()
     */
    @JsonValue
    @Override
    public String toString() {
        return hostname;
    }

    // should deprecate? or still allow it?
    /*
    public static Hostname parse(String input) {
        if (isValid(input)) {
            Hostname h = new Hostname();
            h.hostname = input;
            return h; // new Hostname(input);
        }
        throw new IllegalArgumentException("invalid hostname: " + input);
    }
    * 
    */
    
    // XXX TODO need to extend ObjectModel so we get this for free...
    @Override
    public boolean isValid() {
        return isValid(hostname);
    }

    /**
     * This method does NOT check the network for the existence of the given
     * hostname, it only checks its format for validity and, if an IPv4 or IPv6
     * hostname is given, checks that it is within the allowed range.
     *
     * @param hostname to check for validity, such as 1.2.3.4
     * @return true if the hostname appears to be a valid IPv4 or IPv6 address,
     * false if the hostname is null or otherwise invalid
     */
    public static boolean isValid(String hostname) {
        // right now valid hostname can be any string that does not contain a comma
        return ( !hostname.contains(",") );
        /*
        try {
            if (hostname.contains(":")) {
                // IPv6 format
                URI valid = new URI(String.format("//[%s]", hostname));
                return valid.getHost() != null;
            } else {
                // IPv4 format
                URI valid = new URI(String.format("//%s", hostname));
                return valid.getHost() != null;
            }
        } catch (NullPointerException e) {
            return false; // happens when hostname is null or invalid format like 1b.2.3i.4
        } catch (URISyntaxException e) {
            return false;
        }
        */
    }
    
    @Override
    public int hashCode() {
        return hostname.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Hostname other = (Hostname) obj;
        if ((this.hostname == null) ? (other.hostname != null) : !this.hostname.equals(other.hostname)) {
            return false;
        }
        return true;
    }

    @Override
    public List<Fault> getFaults() {
        if( isValid() ) {
            return Collections.EMPTY_LIST;
        }
        else {
            ArrayList<Fault> faults = new ArrayList<Fault>();
            faults.add(new Fault("Invalid hostname: %s", hostname));            
            return faults;
        }
    }
}
