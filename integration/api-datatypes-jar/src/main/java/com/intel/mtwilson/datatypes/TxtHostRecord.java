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

package com.intel.mtwilson.datatypes;

import com.intel.mtwilson.util.net.Hostname;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;

/**
 * A data transfer object. The TxtHost object is validated on construction
 * so to make it easier to create a TxtHost object, you can put all the data
 * (unvalidated) into a TxtHostRecord and then use it to construct a TxtHost.
 * @author jbuhacoff
 */
//@JsonIgnoreProperties(ignoreUnknown = true)
public class TxtHostRecord {
    @JsonProperty
    public String HostName;
    @JsonProperty
    public String IPAddress;
    @JsonProperty
    public Integer Port;
    @JsonProperty
    public String BIOS_Name;
    @JsonProperty
    public String BIOS_Version;
    @JsonProperty
    public String BIOS_Oem;
    @JsonProperty
    public String VMM_Name;
    @JsonProperty
    public String VMM_Version;
    @JsonProperty
    public String VMM_OSName;
    @JsonProperty
    public String VMM_OSVersion;
    @JsonProperty
    public String AddOn_Connection_String;
    @JsonProperty
    public String Description;
    @JsonProperty
    public String Email;
    @JsonProperty
    public String Location;
    @JsonProperty
    public String AIK_Certificate;
//    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
    public String Hardware_Uuid;
    @JsonProperty
    public String AIK_PublicKey;
    @JsonProperty
    public String AIK_SHA1;
    
    public TxtHostRecord() {
        
    }
    
    public TxtHostRecord(TxtHost input) {
        HostName = input.getHostName().toString();
        if (input.getIPAddress() != null)
            IPAddress = input.getIPAddress().toString();
        else
            IPAddress = "";
        Port = input.getPort();
        BIOS_Name = input.getBios().getName();
        BIOS_Version = input.getBios().getVersion();
        BIOS_Oem = input.getBios().getOem();
        VMM_Name = input.getVmm().getName();
        VMM_Version = input.getVmm().getVersion();
        VMM_OSName = input.getVmm().getOsName();
        VMM_OSVersion = input.getVmm().getOsVersion();
        AddOn_Connection_String = input.getAddOn_Connection_String();
        Description = input.getDescription();
        Email = input.getEmail();
        Location = input.getLocation();
        AIK_Certificate = input.getAikCertificate();
        Hardware_Uuid = null;
//        AIK_PublicKey = input.getAikPublicKey();
//        AIK_SHA1 = input.getAikSha1();
    }
}
