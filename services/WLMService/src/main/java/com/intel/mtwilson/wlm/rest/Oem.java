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

import com.intel.mtwilson.wlm.business.OemBO;
import com.intel.mtwilson.datatypes.OemData;
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
@Path("/oem")
public class Oem {  

    
    private OemBO oemBo;

    /** Creates a new instance of Oem */
    public Oem() {
        oemBo = new OemBO();
    }

    /**
     * Retrieves representation of list of all instances of com.intel.mountwilson.wlm.rest.OEM
     * in the database
     * @return an instance of 
     */
    @GET
    @Produces("application/json")
    public List<OemData> listAllOem() {
        return oemBo.getAllOem();
    }

    /**
     * Updates the specified OME in the database. If it can be updated a success message
     * is returned. If not, an error message is returned.
     * Sample request:
     * PUT http://localhost:8080/WLMService/resources/oem
     * {"Name":"OME Name ","Version":"Os Version","Description":"Os Description"}
     * Sample success output:
     * "true"
     * Sample error output:
     * { "error_message":"Unknown error - Error while updating OEM in WLM Service", "error_code":1002 }
     * 
     * @param oemData record as described
     * @return 
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String updateOem(OemData oemData) {
        return oemBo.updateOem(oemData);
    }
    /**
     * Adds the specified Oem in the database. If it can be added a success message
     * is returned. If not, an error message is returned.
     * Sample request:
     * PUT http://localhost:8080/WLMService/resources/oem
     * {"Name":"Oem Name ","Description":"Oem Description"}
     * Sample success output:
     * "true"
     * Sample error output:
     * { "error_message":"Unknown error - Error while creating OEM in WLM Service", "error_code":1002 }
     * 
     * @param oemData record as described
     * @return 
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String addOem(OemData oemData) {
        return oemBo.createOem(oemData,"");
    }
    
    /**
     * Deletes the specified Oem in the database. If it can be deleted a success message
     * is returned. If not, an error message is returned.
     * Sample request:
     * PUT http://localhost:8080/WLMService/resources/oem
     * {"Name":"Oem Name ","Description":"Oem Description"}
     * Sample success output:
     * "true"
     * Sample error output:
     * { "error_message":"Unknown error - Error while creating OEM in WLM Service", "error_code":1002 }
     * 
     * @param oemData record as described
     * @return 
     */   
    @DELETE
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public String deleteOem(@QueryParam("Name")String oemName ) {
        return oemBo.deleteOem(oemName);
    }
    
    

}
