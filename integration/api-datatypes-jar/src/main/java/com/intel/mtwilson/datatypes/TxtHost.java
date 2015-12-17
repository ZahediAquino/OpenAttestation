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
import org.codehaus.jackson.annotate.JsonCreator;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dsmagadx
 */
public class TxtHost {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private Hostname hostname;
//    private ServicePort servicePort;
    private IPAddress ipAddress;
    private Integer port;
    private String connectionString;
    private Bios bios;
    private Vmm vmm;
    private String description;
    private String email;
    private String location;
    private HostTrustStatus trustStatus;
    private String aikCertificate;  // may be null

    public TxtHost(TxtHostRecord host, HostTrustStatus trustStatus) {
        this(host);
        this.trustStatus = new HostTrustStatus(trustStatus); // make our own copy
    }
    
    /**
     * To create a new TxtHost instance, you call the constructor with
     * a TxtHostRecord structure. 
     * @param host 
     */
    @JsonCreator
    public TxtHost(TxtHostRecord host /*
            @JsonProperty("HostName")  String HostName,
            @JsonProperty("IPAddress")  String IPAddress,
            @JsonProperty("Port")  Integer Port,
            @JsonProperty("BIOS_Name")  String BIOS_Name,
            @JsonProperty("BIOS_Version")  String BIOS_Version,
            @JsonProperty("VMM_Name")  String VMM_Name,
            @JsonProperty("VMM_Version")  String VMM_Version,
            @JsonProperty("AddOn_Connection_String")  String AddOn_Connection_String,
            @JsonProperty("Description")  String Description,
            @JsonProperty("Email")  String Email */) {
        hostname = new Hostname(host.HostName);
        bios = new Bios(host.BIOS_Name, host.BIOS_Version, host.BIOS_Oem);
        vmm = new Vmm(host.VMM_Name, host.VMM_Version, host.VMM_OSName, host.VMM_OSVersion);
        ipAddress = (host.IPAddress == null || host.IPAddress.isEmpty()) ? null : new IPAddress(host.IPAddress);
        port = host.Port;
        connectionString = host.AddOn_Connection_String;
        description = host.Description;
        email = host.Email;
        location = host.Location;
        trustStatus = new HostTrustStatus(); //defaults to all false
        aikCertificate = host.AIK_Certificate; // may be null

    }

    // Sample JSON output (not used)
    // {"hostName":"RHEL 62 KVM","port":9999,"description":"RHEL 62 KVM Integration ENV","addOn_Connection_String":"http://example.server.com:234/vcenter/","bios":{"name":"EPSD","version":"60"},"vmm":{"name":"ESX","version":"0.4.1"},"ipaddress":"10.1.71.103","email":null}
    public Hostname getHostName() {
        return hostname;
    }

    public Bios getBios() {
        return bios;
    }

    public Vmm getVmm() {
        return vmm;
    }

    public IPAddress getIPAddress() {
        return ipAddress;
    }

    public Integer getPort() {
        return port;
    }

    public String getAddOn_Connection_String() {
        if( connectionString == null && ipAddress != null && port != null ) {
            // for backwards compatibility with cilents that don't submit a connection string for intel hosts
              log.debug("stdalex connection string was null");
              return "intel:https://"+ipAddress.toString()+":"+port.toString(); // XXX or mabye just throw an IllegalArgumentException , this may not be the right place to kludge this.
        }
        return connectionString;
    }
    
    public String getVendor() {
        // We assume connectionString starts with either "intel:", "vmware:" or "citrix" prefixes
        String vendor  = getAddOn_Connection_String().substring(0, getAddOn_Connection_String().indexOf(":"));
        log.debug("Vendor calculated :" + vendor);
        return vendor;
        
    }

    public String getDescription() {
        return description;
    }

    public String getEmail() {
        return email;
    }

    public String getLocation() {
        return location;
    }
    
    public String getAikCertificate() {
        return aikCertificate;
    }

    final public boolean requiresConnectionString() {
        // BUG #497  now every host requies a connection string 
        return true; /*
        if (vmm.getName().toUpperCase().contains("ESX")) {
            return true;
        }
        return false;*/
    }
    
    final public boolean isBiosTrusted() { return trustStatus.bios; }
    final public boolean isVmmTrusted() { return trustStatus.vmm; }
    final public boolean isLocationTrusted() { return trustStatus.location; }
    final public boolean isAssetTagTrusted() { return trustStatus.asset_tag; }
}
