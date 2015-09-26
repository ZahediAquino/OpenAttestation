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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.wlm.rest;

import com.intel.mtwilson.wlm.business.OsBO;
import com.intel.mtwilson.datatypes.OsData;
import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

/**
 * REST Web Service
 *
 * @author dsmagadx
 */
@Path("/os")
public class Os {

    
    private OsBO osBO;

    /** Creates a new instance of Os */
    public Os() {
        osBO = new OsBO();
    }

    /**
     * Retrieves representation of list of all instances of com.intel.mountwilson.wlm.rest.Os
     * in the database
     * @return an instance of 
     */
    @GET
    @Produces("application/json")
    public List<OsData> listAllOs() {
        return osBO.getAllOs();
    }

    /**
     * Updates the specified OS in the database. If it can be updated a success message
     * is returned. If not, an error message is returned.
     * Sample request:
     * PUT http://localhost:8080/WLMService/resources/os
     * {"Name":"OS Name ","Version":"Os Version","Description":"Os Description"}
     * Sample success output:
     * "true"
     * Sample error output:
     * { "error_message":"Unknown error - Error while creating MLE in WLM Service", "error_code":1002 }
     * 
     * @param osData record as described
     * @return 
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String updateOs(OsData osData) {
        return osBO.updateOs(osData);
    }
    /**
     * Adds the specified OS in the database. If it can be added a success message
     * is returned. If not, an error message is returned.
     * Sample request:
     * PUT http://localhost:8080/WLMService/resources/os
     * {"Name":"OS Name ","Version":"Os Version","Description":"Os Description"}
     * Sample success output:
     * "true"
     * Sample error output:
     * { "error_message":"Unknown error - Error while creating MLE in WLM Service", "error_code":1002 }
     * 
     * @param osData record as described
     * @return 
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String addOs(OsData osData) {
        return osBO.createOs(osData,"");
    }
    
    
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String deleteOs(@QueryParam("Name")String osName, @QueryParam("Version")String osVersion ) {
        return osBO.deleteOs(osName,osVersion);
    }
    
    

}
