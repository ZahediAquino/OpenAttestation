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
import com.intel.mtwilson.as.controller.TblOemJpaController;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblOem;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.datatypes.OemData;
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
public class OemBO extends BaseBO {

    Logger log = LoggerFactory.getLogger(getClass().getName());
    TblOemJpaController tblOemJpaController = null;

    public OemBO() {
        tblOemJpaController = new TblOemJpaController(getEntityManagerFactory());
    }

    /**
     * 
     * @return 
     */
    public List<OemData> getAllOem() {
        List<OemData> allOemData = new ArrayList<OemData>();
        try {
            List<TblOem> allRecords = tblOemJpaController.findTblOemEntities();

            for (TblOem tblOem : allRecords) {
                OemData oemData = new OemData(tblOem.getName(), tblOem.getDescription());
                allOemData.add(oemData);
            }

        }catch(ASException ase){
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }


        return allOemData;
    }

    /**
     * 
     * @param oemData
     * @return 
     */
    public String updateOem(OemData oemData) {

        try {
            TblOem tblOem = tblOemJpaController.findTblOemByName(oemData.getName());
            
            if(tblOem == null)
                throw new ASException(ErrorCode.WS_OEM_DOES_NOT_EXIST, oemData.getName());
            
            tblOem.setDescription(oemData.getDescription());
            
            tblOemJpaController.edit(tblOem);
            
        } catch(ASException ase){
            throw ase;
        } catch (Exception e) {
            
            throw new ASException(e);
        }
        return "true";
    }

    /**
     * 
     * @param oemData
     * @return 
     */
    public String createOem(OemData oemData, String uuid) {
        try {
            TblOem tblOem = tblOemJpaController.findTblOemByName(oemData.getName());
            
            if(tblOem != null)
                throw new ASException(ErrorCode.WS_OEM_ALREADY_EXISTS, oemData.getName());
            
            tblOem = new TblOem();
            tblOem.setName(oemData.getName());
            tblOem.setDescription(oemData.getDescription());
            if (uuid != null && !uuid.isEmpty()) {
                tblOem.setUuid_hex(uuid);
            } else {
                tblOem.setUuid_hex(new UUID().toString());
            }
            tblOemJpaController.create(tblOem);
            
        } catch(ASException ase){
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }
        return "true";
    }

    /**
     * 
     * @param osName
     * @return 
     */
    public String deleteOem(String osName) {
        try{
            TblOem tblOem = tblOemJpaController.findTblOemByName(osName);
            
            if(tblOem == null){
                throw new ASException(ErrorCode.WS_OEM_DOES_NOT_EXIST, osName);
            }
            
            Collection<TblMle> tblMleCollection = tblOem.getTblMleCollection();
            if( tblMleCollection != null ) {
                log.info("OEM is currently associated with # MLEs: " + tblMleCollection.size());
            
                if(!tblMleCollection.isEmpty()){
                    throw new ASException(ErrorCode.WS_OEM_ASSOCIATION_EXISTS, osName, tblMleCollection.size());
                }
            }
            
            tblOemJpaController.destroy(tblOem.getId());
            } catch(ASException ase){
                throw ase;
                 
            } catch (Exception e) {
                throw new ASException(e);
            }
        return "true";
    }
}
