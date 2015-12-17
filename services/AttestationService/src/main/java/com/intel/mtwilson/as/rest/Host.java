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


package com.intel.mtwilson.as.rest;

import javax.ejb.Stateless;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import com.intel.mtwilson.util.net.Hostname;
import com.intel.mtwilson.as.business.HostBO;
import com.intel.mtwilson.as.business.trust.HostTrustBO;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.helper.ASComponentFactory;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.util.validation.ValidationUtil;
//import javax.annotation.security.RolesAllowed;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import javax.ws.rs.DefaultValue;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import org.codehaus.enunciate.jaxrs.TypeHint;

/**
 * REST Web Service
 * * 
 */

@Stateless
@Path("/hosts")
public class Host {
    private HostBO hostBO = new ASComponentFactory().getHostBO(); 
    
    // variable declaration used for Logging.  
        Logger log = LoggerFactory.getLogger(getClass().getName());
    

    /**
     * Returns the location of a host.
     * 
     * Sample request:
     * GET http://localhost:8080/AttestationService/resources/hosts/location?hostName=Some+TXT+Host
     * 
     * Sample output:
     * San Jose
     * 
     * @param hostName unique name of the host to query
     * @return the host location
     */
    @GET
    @Produces({MediaType.APPLICATION_JSON})
    @Path("/location")
    public HostLocation getLocation(@QueryParam("hostName")String hostName) {
            return new ASComponentFactory().getHostTrustBO().getHostLocation(new Hostname(hostName)); // datatype.Hostname            
    }

    @POST
    @Produces({MediaType.APPLICATION_JSON})
    @Path("/location")
    public String addLocation(HostLocation hlObj) {
        Boolean result = new ASComponentFactory().getHostTrustBO().addHostLocation(hlObj); 
        return Boolean.toString(result);
    }
    /**
     * Returns the trust status of a host.
     * 
     * Sample request:
     * GET http://localhost:8080/AttestationService/resources/hosts/trust?hostName=Some+TXT+Host
     * 
     * Sample output for untrusted host:
     * BIOS:0,VMM:0
     * 
     * Sample output for trusted host:
     * BIOS:1,VMM:1
     * 
     * @param hostName unique name of the host to query
     * @return a string like BIOS:0,VMM:0 representing the trust status
     */
    @GET
    @Produces({MediaType.APPLICATION_JSON})
    @Path("/trust")
    public HostTrustResponse get(@QueryParam("hostName")String hostName) {
        try {
            // 0.5.1 returned MediaType.TEXT_PLAIN string like "BIOS:0,VMM:0" :  return new HostTrustBO().getTrustStatusString(new Hostname(hostName)); // datatype.Hostname            
            Hostname hostname = new Hostname(hostName);
            HostTrustStatus trust = new ASComponentFactory().getHostTrustBO().getTrustStatus(hostname);
            return new HostTrustResponse(hostname, trust);
        }
        catch(ASException e) {
            throw e;
        }catch(Exception e) {
            throw new ASException(e);
        }
    }

    
    /**
     * Adds a new host to the database. This action involves contacting the host
     * to obtain trust-related information. If the host is offline, the request
     * will fail.
     * 
     * Required parameters for all hosts are host name, BIOS name and version, 
     * and VMM name and version. If the host is an ESX host then the vCenter
     * connection URL is also required. Otherwise, the host IP address and port
     * are required. Host description and contact email are optional.
     * 
     * Parameter names:
     *   HostName
     *   IPAddress
     *   Port
     *   BIOS_Name
     *   BIOS_Version
     *   BIOS_Oem
     *   VMM_Name
     *   VMM_Version
     *   VMM_OSName
     *   VMM_OSVersion
     *   AddOn_Connection_String
     *   Description
     *   Email
     * 
     * @param host a form containing the above parameters
     * @return error status
     * 
     * Response:
     * {"error_code":"",error_message:""}
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public String post(TxtHostRecord hostRecord) {
         return hostBO.addHost(new TxtHost(hostRecord)); 
    }
    
    /**
     * Updates an existing host in the database. This action involves contacting 
     * the host to obtain trust-related information. If the host is offline, the 
     * request will fail.
     * 
     * Required parameters for all hosts are host name, BIOS name and version, 
     * and VMM name and version. If the host is an ESX host then the vCenter
     * connection URL is also required. Otherwise, the host IP address and port
     * are required. Host description and contact email are optional.
     * 
     * Parameter names:
     *   HostName
     *   IPAddress
     *   Port
     *   BIOS_Name
     *   BIOS_Version
     *   VMM_Name
     *   VMM_Version
     *   AddOn_Connection_String
     *   Description
     *   Email
     * 
     * 
     * @param host a form containing the above parameters
     * @return error status
     */
    @PUT
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    public String put(TxtHostRecord hostRecord) {
            return hostBO.updateHost(new TxtHost(hostRecord));
    }
    
    /**
     * Deletes a host from the database. 
     * 
     * Example request:
     * DELETE http://localhost:8080/AttestationService/resources/hosts?hostName=Some+TXT+Host
     * 
     * @param hostName the unique host name of the host to delete
     * @return error status
     */
    @DELETE
//    @Consumes({"text/html"})
    @Produces({MediaType.APPLICATION_JSON})
    public String delete(@QueryParam("hostName")String hostName){
           return hostBO.deleteHost(new Hostname(hostName));
     }
    
    
//    @GET
//    @Produces({MediaType.APPLICATION_JSON})
//    public List<TxtHostRecord> queryForHosts(@QueryParam("searchCriteria")String searchCriteria) {
//            return hostBO.queryForHosts(searchCriteria);
//    }
    
     /**
         * 
         * @param searchCriteria optional, a string that would be contained in the host name;  if not specified you will get a list of all the hosts
         * @return list of hosts whose hostname contains the value specified by searchCriteria;  in SQL terms, WHERE hostname LIKE '%searchCriteria%'
         */
        //@RolesAllowed({"Attestation", "Report", "Security"})
        @RequiresPermissions("hosts:search") 
        @GET
        @Produces({MediaType.APPLICATION_JSON})
        public List<TxtHostRecord> queryForHosts(
                    @QueryParam("searchCriteria") String searchCriteria,
                    @QueryParam("includeHardwareUuid")  @DefaultValue("false") boolean includeHardwareUuid) {
                    //@QueryParam("includeTlsPolicy")  @DefaultValue("false") boolean includeTlsPolicy) {
            //log.debug("queryForHosts api searchCriteria["+searchCriteria+"] ");
            ValidationUtil.validate(searchCriteria);
                //if( searchCriteria == null || searchCriteria.isEmpty() ) { throw new ValidationException("Missing hostNames parameter"); }
                //else 
            List<TxtHostRecord> resultset;
            if(includeHardwareUuid) {
                log.info("include hardware_uuid=true, call queryForHosts(searchCriteria,includeHardwareUuid)");
                resultset = hostBO.queryForHosts(searchCriteria,includeHardwareUuid);
            }else{
                log.info("include hardware_uuid=false, call queryForHosts(searchCriteria)");
                resultset = hostBO.queryForHosts(searchCriteria);
            }
            
            /*
            if( !includeTlsPolicy ) {
                for(TxtHostRecord record : resultset) {
                    record.tlsPolicyChoice = null;
                }
            }*/
            return resultset;
        }
    
    
}
