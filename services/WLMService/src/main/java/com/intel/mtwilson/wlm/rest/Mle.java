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
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 1997-2010 Oracle and/or its affiliates. All rights reserved.
 *
 * Oracle and Java are registered trademarks of Oracle and/or its affiliates.
 * Other names may be trademarks of their respective owners.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common
 * Development and Distribution License("CDDL") (collectively, the
 * "License"). You may not use this file except in compliance with the
 * License. You can obtain a copy of the License at
 * http://www.netbeans.org/cddl-gplv2.html
 * or nbbuild/licenses/CDDL-GPL-2-CP. See the License for the
 * specific language governing permissions and limitations under the
 * License.  When distributing the software, include this License Header
 * Notice in each file and include the License file at
 * nbbuild/licenses/CDDL-GPL-2-CP.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the GPL Version 2 section of the License file that
 * accompanied this code. If applicable, add the following below the
 * License Header, with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * 
 * Contributor(s):
 * 
 * The Original Software is NetBeans. The Initial Developer of the Original
 * Software is Sun Microsystems, Inc. Portions Copyright 1997-2007 Sun
 * Microsystems, Inc. All Rights Reserved.
 * 
 * If you wish your version of this file to be governed by only the CDDL
 * or only the GPL Version 2, indicate your decision by adding
 * "[Contributor] elects to include this software in this distribution
 * under the [CDDL or GPL Version 2] license." If you do not indicate a
 * single choice of license, a recipient has the option to distribute
 * your version of this file under either the CDDL, the GPL Version 2 or
 * to extend the choice of license to its licensees as provided above.
 * However, if you add GPL Version 2 code and therefore, elected the GPL
 * Version 2 license, then the option applies only if the new code is
 * made subject to such option by the copyright holder.
 */
package com.intel.mtwilson.wlm.rest;

import com.intel.mtwilson.wlm.business.MleBO;
import com.intel.mtwilson.datatypes.MleData;
import com.intel.mtwilson.datatypes.MleSource;
import com.intel.mtwilson.datatypes.PCRWhiteList;
import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import javax.ws.rs.Path;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Produces;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

/**
 * REST Web Service
 *
 * @author mkuchtiak
 */
@Stateless
@Path("/mles")
public class Mle {

    MleBO mleBO = new MleBO();

    /**
     * Adds the specified MLE to the database. If it can be added a success message
     * is returned. If not, an error message is returned.
     * Sample request:
     * POST http://localhost:8080/WLMService/resources/mles
     * {"Name":"OEM MLE A","Description":"OEM MLE Revised","Attestation_Type":"PCR","MLE_Manifests":[{"Name":"1","Value":"abcdefghijklmnop"},{"Name":"2","Value":"jklmnopabcdefghi"}],"MLE_Type":"VMM","Version":"1.2.3"}
     * Sample success output:
     * "true"
     * Sample error output:
     * { "error_message":"Unknown error - Error while creating MLE in WLM Service", "error_code":1002 }
     * 
     * @param mleData record as described
     * @return 
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String addMle(MleData mleData) {
        return mleBO.addMLe(mleData,"");
    }

    /**
     * Updates the specified MLE to the database. If it can be updated a success message
     * is returned. If not, an error message is returned.
     * Sample request:
     * PUT http://localhost:8080/WLMService/resources/mles
     * {"Name":"OEM MLE A","Description":"OEM MLE Revised","Attestation_Type":"PCR","MLE_Manifests":[{"Name":"1","Value":"abcdefghijklmnop"},{"Name":"2","Value":"jklmnopabcdefghi"}],"MLE_Type":"VMM","Version":"1.2.3"}
     * Sample success output:
     * "true"
     * Sample error output:
     * { "error_message":"Unknown error - Error while creating MLE in WLM Service", "error_code":1002 }
     * 
     * @param mleData record as described
     * @return 
     */
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String updateMle(MleData mleData) {
        return mleBO.updateMle(mleData);
    }

    /**
     * Returns the name, version, MLE type, description, attestation type, and manifests (list) for all MLEs that
     * match the search criteria.
     * 
     * Searches for all MLEs with a name matching the search term. For example,
     * if the database contains MLE with name "OEM SW A" and "OEM SW B"
     * then a searchCriteria of "OEM" would return both, whereas "SW A" would
     * return only "OEM SW A".
     * 
     * Sample request:
     * http://localhost:8080/WLMService/resources/mles?searchCriteria=EPSD
     * Sample output:
     * [
     *   {"Name":"EPSD","Version":"55","MLE_Type":"BIOS","Description":"","Attestation_Type":"PCR",
     *    "MLE_Manifests":[{"Name":"0","Value":"E3A29BD603BF9982113B696CD37AF8AFC58E2877"}]},
     *   {"Name":"EPSD","Version":"60","MLE_Type":"BIOS","Description":"","Attestation_Type":"PCR",
     *    "MLE_Manifests":[{"Name":"0","Value":"5E724D834FEC48C62D523D95D08884DCAC7F4F98"}]},
     *   {"Name":"EPSD","Version":"58","MLE_Type":"BIOS","Description":"","Attestation_Type":"PCR",
     *    "MLE_Manifests":[{"Name":"0","Value":"365A73E405821F88A68346E73F2FDA1215C03696"}]}
     * ]
     * 
     * @param searchCriteria a portion of the MLE name to search. 
     * @return 
     */
    @GET
//    @Consumes(MediaType.TEXT_HTML)
    @Produces(MediaType.APPLICATION_JSON)
    public List<MleData> queryForMLE(@QueryParam("searchCriteria") String searchCriteria) {
        return mleBO.listMles(searchCriteria);
    }

    /**
     * Returns the name, version, MLE type, description, attestation type, and manifests (list) for the specified MLE.
     * Sample request:
     * GET http://localhost:8080/WLMService/resources/mles/manifest?mleName=EPSD&mleVersion=60
     * Sample response:
     * {"Name":"EPSD","Version":"60","MLE_Type":"BIOS","Description":"","Attestation_Type":"PCR","MLE_Manifests":[{"Name":"0","Value":"5E724D834FEC48C62D523D95D08884DCAC7F4F98"}]}
     * 
     * @param mleName
     * @param mleVersion
     * @return 
     */
    @GET
    @Path("/manifest")
//    @Consumes(MediaType.TEXT_HTML)
    @Produces(MediaType.APPLICATION_JSON)
    public MleData getMLEDetails(
            @QueryParam("mleName") String mleName,
            @QueryParam("mleVersion") String mleVersion,
            @QueryParam("osName") String osName,
            @QueryParam("osVersion") String osVersion,
            @QueryParam("oemName") String oemName) {
        return mleBO.findMle(mleName, mleVersion, osName, osVersion, oemName);
    }

    /**
     * Deletes an MLE from the database. The MLE is specified by name and version.
     * If successful, the string "true" will be returned.
     * 
     * Sample request:
     * DELETE http://localhost:8080/WLMService/resources/mles?mleName=EPSD&mleVersion=60
     * Sample response:
     * "true"
     * 
     * @param mleName
     * @param mleVersion
     * @return 
     */
    @DELETE
//    @Consumes(MediaType.TEXT_HTML)
    @Produces(MediaType.APPLICATION_JSON)
    public String deleteMle(
            @QueryParam("mleName") String mleName, 
            @QueryParam("mleVersion") String mleVersion,
            @QueryParam("osName") String osName,
            @QueryParam("osVersion") String osVersion,
            @QueryParam("oemName") String oemName) {
        return mleBO.deleteMle(mleName, mleVersion,osName, osVersion, oemName);
    }
    
    /**
     * Added By: Sudhir on June 20, 2012
     * 
     * Process the add request into the PCR manifest table.
     * 
     * @param pcrData : White List data to be added to the PCR Manifest table
     * @return : "true" if success or else exception.
     */
    @POST
    @Path("/whitelist/pcr")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String addPCRWhiteList(PCRWhiteList pcrData) {
        return mleBO.addPCRWhiteList(pcrData);
    }

    /**
     * Added By: Sudhir on June 20, 2012
     * 
     * Processes the update request into the PCR manifest table.
     * 
     * @param pcrData : White List data to be updated in the PCR Manifest table
     * @return : "true" if success or else exception.
     */
    @PUT
    @Path("/whitelist/pcr")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String updatePCRWhiteList(PCRWhiteList pcrData) {
        return mleBO.updatePCRWhiteList(pcrData);
    }
    
    /**
     * Added By: Sudhir on June 20, 2012
     * 
     * Processes the delete request from the PCR manifest table.
     * 
     * @param pcrName : Name of the PCR entry that needs to be deleted.
     * @param mleName : Name of the measured launch environment (MLE) associated with the white list.
     * @param mleVersion : Version of the MLE or Hypervisor
     * @param osName : Name of the OS running the hypervisor. OS Details need to be provided only
     * when the associated MLE is of VMM type.
     * @param osVersion : Version of the OS
     * @param oemName : OEM vendor of the hardware system. OEM Details have to be provided only 
     * when the associated MLE is of BIOS type.
     * @return : "true" if success or else exception.
     */
    @DELETE
    @Path("/whitelist/pcr")
    @Produces(MediaType.TEXT_PLAIN)
    public String deletePCRWhiteList(
            @QueryParam("pcrName") String pcrName,
            @QueryParam("mleName") String mleName, 
            @QueryParam("mleVersion") String mleVersion,
            @QueryParam("osName") String osName,
            @QueryParam("osVersion") String osVersion,
            @QueryParam("oemName") String oemName) {
        return mleBO.deletePCRWhiteList(pcrName, mleName, mleVersion,osName, osVersion, oemName);
    }

    @POST
    @Path("/source")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String addMleSource(MleSource mleSourceObj) {
        return mleBO.addMleSource(mleSourceObj);
    }

    @PUT
    @Path("/source")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.TEXT_PLAIN)
    public String updateMleSource(MleSource mleSourceObj) {
        return mleBO.updateMleSource(mleSourceObj);
    }

    @DELETE
    @Path("/source")
    @Produces(MediaType.TEXT_PLAIN)
    public String deleteMleSource(
            @QueryParam("mleName") String mleName, 
            @QueryParam("mleVersion") String mleVersion,
            @QueryParam("osName") String osName,
            @QueryParam("osVersion") String osVersion,
            @QueryParam("oemName") String oemName) {
        return mleBO.deleteMleSource(mleName, mleVersion, osName, osVersion, oemName);
    }

    @GET
    @Path("/source")
    @Produces(MediaType.APPLICATION_JSON)
    public String getMleSource(
            @QueryParam("mleName") String mleName, 
            @QueryParam("mleVersion") String mleVersion,
            @QueryParam("osName") String osName,
            @QueryParam("osVersion") String osVersion,
            @QueryParam("oemName") String oemName) {
        return mleBO.getMleSource(mleName, mleVersion, osName, osVersion, oemName);
    }
    
}
