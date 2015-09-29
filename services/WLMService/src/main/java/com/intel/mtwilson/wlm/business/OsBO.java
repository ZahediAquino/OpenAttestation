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
package com.intel.mtwilson.wlm.business;

import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.controller.TblOsJpaController;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblOs;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.datatypes.OsData;
import com.intel.mtwilson.util.io.UUID;
import com.intel.mtwilson.wlm.helper.BaseBO;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author dsmagadx
 */
public class OsBO extends BaseBO {

    Logger log = LoggerFactory.getLogger(getClass().getName());
    TblOsJpaController tblOsJpaController = null;

    public OsBO() {
        tblOsJpaController = new TblOsJpaController(getEntityManagerFactory());
    }

    /**
     * 
     * @return 
     */
    public List<OsData> getAllOs() {
        List<OsData> allOsData = new ArrayList<OsData>();
        try {
            List<TblOs> allRecords = tblOsJpaController.findTblOsEntities();

            for (TblOs tblOs : allRecords) {
                OsData osData = new OsData(tblOs.getName(), tblOs.getVersion(), tblOs.getDescription());
                allOsData.add(osData);
            }

        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }


        return allOsData;
    }

    /**
     * 
     * @param osData
     * @return 
     */
    public String updateOs(OsData osData) {

        try {
            TblOs tblOs = tblOsJpaController.findTblOsByNameVersion(osData.getName(), osData.getVersion());

            if (tblOs == null) {
                throw new ASException(ErrorCode.WS_OS_DOES_NOT_EXIST, osData.getName(), osData.getVersion());
            }

            tblOs.setDescription(osData.getDescription());

            tblOsJpaController.edit(tblOs);

        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }
        return "true";
    }

    /**
     * 
     * @param osData
     * @return 
     */
    public String createOs(OsData osData, String uuid) {
        try {
            TblOs tblOs = tblOsJpaController.findTblOsByNameVersion(osData.getName(), osData.getVersion());

            if (tblOs != null) {
                throw new ASException(ErrorCode.WS_OS_ALREADY_EXISTS, osData.getName(), osData.getVersion());
            }

            tblOs = new TblOs();
            tblOs.setName(osData.getName());
            tblOs.setVersion(osData.getVersion());
            tblOs.setDescription(osData.getDescription());
            if (uuid != null && !uuid.isEmpty()) {
                tblOs.setUuid_hex(uuid);
            } else {
                tblOs.setUuid_hex(new UUID().toString());
            }
            tblOsJpaController.create(tblOs);

        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }
        return "true";
    }

    /**
     * 
     * @param osName
     * @param osVersion
     * @return 
     */
    public String deleteOs(String osName, String osVersion) {
        try {
            TblOs tblOs = tblOsJpaController.findTblOsByNameVersion(osName, osVersion);

            if (tblOs == null) {
                throw new ASException(ErrorCode.WS_OS_DOES_NOT_EXIST,osName, osVersion);                
            }
            
            Collection<TblMle> tblMleCollection = tblOs.getTblMleCollection();
            if( tblMleCollection != null ) {
                log.info("OS is currently associated with # MLEs: " + tblMleCollection.size());
            
                if(!tblMleCollection.isEmpty()){
                      throw new ASException(ErrorCode.WS_OS_ASSOCIATION_EXISTS, osName, osVersion, tblMleCollection.size());
                }
            }
            tblOsJpaController.destroy(tblOs.getId());
            
        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }
        return "true";
    }
}
