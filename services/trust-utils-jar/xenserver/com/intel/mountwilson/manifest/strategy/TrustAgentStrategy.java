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

package com.intel.mountwilson.manifest.strategy;

import java.util.HashMap;

import javax.persistence.EntityManagerFactory;

import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.controller.TblMleJpaController;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mountwilson.manifest.IManifestStrategy;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.helper.TAHelper;
import com.intel.mtwilson.datatypes.ErrorCode;

/**
 * XXX needs to move to a trust-agent specific package
 */
public class TrustAgentStrategy extends TAHelper implements IManifestStrategy {

    EntityManagerFactory entityManagerFactory;
    
	public TrustAgentStrategy(EntityManagerFactory entityManagerFactory)
			 {
		this.entityManagerFactory = entityManagerFactory;
	}

	public EntityManagerFactory getEntityManagerFactory() {
		return entityManagerFactory;
	}
	
	public void setEntityManagerFactory(EntityManagerFactory entityManagerFactory) {
		this.entityManagerFactory = entityManagerFactory;
	}
        
        // BUG #497 the Map<String,? extends IManifest> needs to be replaced with the new PcrManifest model object.  (do not confuse:  there is an implementation of IManifest called PcrManiest - NOT the same one)
	@Override
	public HashMap<String, ? extends IManifest> getManifest(TblHosts tblHosts) {
		
		
		String pcrList = getPcrList(tblHosts);
                
                // Important:  If this host is already registered then its record will have an AIK certificate... in that case, we need to use the
                // known AIK certificate of the host to verify its quote.
                if( tblHosts.getAIKCertificate() != null ) {
                    setTrustedAik(tblHosts.getAIKCertificate());
                }
		
		
		return getQuoteInformationForHost(tblHosts, pcrList); // tblHosts.getIPAddress(), pcrList, tblHosts.getName(), tblHosts.getPort());
		
		
	}
	
    private String getPcrList(TblHosts tblHosts) {
        
        // Get the Bios MLE without accessing cache
        
        TblMle biosMle = new TblMleJpaController(getEntityManagerFactory()).findMleById(tblHosts.getBiosMleId().getId());
        
        String biosPcrList = biosMle.getRequiredManifestList();

        if (biosPcrList.isEmpty()) {
            throw new ASException(ErrorCode.AS_MISSING_MLE_REQD_MANIFEST_LIST, tblHosts.getBiosMleId().getName(), tblHosts.getBiosMleId().getVersion());
        }

        // Get the Vmm MLE without accessing cache
        TblMle vmmMle = new TblMleJpaController(getEntityManagerFactory()).findMleById(tblHosts.getVmmMleId().getId());

        String vmmPcrList = vmmMle.getRequiredManifestList();

        if (vmmPcrList == null || vmmPcrList.isEmpty()) {
            throw new ASException(ErrorCode.AS_MISSING_MLE_REQD_MANIFEST_LIST, tblHosts.getVmmMleId().getName(), tblHosts.getVmmMleId().getVersion());
        }

        return biosPcrList + "," + vmmPcrList;

    }

}
