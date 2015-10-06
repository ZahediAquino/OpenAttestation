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

/**
 * This Class contains all Method for MLE Component (Add, Edit, View and Delete)
 */
package com.intel.mountwilson.Service;

import java.util.List;
import com.intel.mountwilson.common.WLMPortalException;
import com.intel.mountwilson.datamodel.MLEDataVO;
import com.intel.mountwilson.util.ConnectionUtil;
import com.intel.mountwilson.util.ConverterUtil;
import com.intel.mtwilson.WhitelistService;
import com.intel.mtwilson.datatypes.MLESearchCriteria;
import com.intel.mtwilson.datatypes.MleData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * @author Yuvraj Singh
 *
 */
public class MLEClientServiceImpl implements IMLEClientService {
        Logger log = LoggerFactory.getLogger(getClass().getName());
	
	public MLEClientServiceImpl(){
		
	}
	
	
	/**
	 * Method to get List of all MLEs types.
	 * 
	 * @param apiClientServices
	 * @return
	 * @throws WLMPortalException
	 */
	@Override
	public List<MLEDataVO> getAllMLE(WhitelistService apiClientServices) throws WLMPortalException {
		log.info("MLEClientServiceImpl.getAllMLE >>");
		List<MLEDataVO> list = null;
                                try {
                                        list =ConverterUtil.getListToMLEDataVO(apiClientServices.searchMLE(""));
                                }catch (Exception e) {
                                                        throw ConnectionUtil.handleException(e);
                                }
                                log.info("MLEClientServiceImpl.getAllMLE <<");
                                return list;
	}

	/**
	 * Method to add MLE Type into a rest services using Api CLient Object.
	 * 
	 * @param dataVO : contain details of MLE to be Added.
	 * @param apiClientServices
	 * @return
	 * @throws WLMPortalException 
	 */
	@Override
	public boolean addMLEInfo(MLEDataVO dataVO,WhitelistService apiClientServices) throws WLMPortalException {
		log.info("MLEClientServiceImpl.addMLEInfo >>");
		boolean result = false;
		try {
			result = apiClientServices.addMLE(ConverterUtil.getMleApiClientObject(dataVO));
		} catch (Exception e) {
			log.error(e.getMessage());
			throw ConnectionUtil.handleException(e);
		}
                                                 log.info("MLEClientServiceImpl.addMLEInfo <<");
       	
       	return result;
	}

	/**
	 * Method to update MLE Type into a rest services
	 * 
	 * @param dataVO
	 * @param apiClientServices
	 * @return Boolean variable e.g true if MLE is updated successfully 
	 * @throws WLMPortalException
	 */
	@Override
	public boolean updateMLEInfo(MLEDataVO dataVO,WhitelistService apiClientServices) throws WLMPortalException {
		log.info("MLEClientServiceImpl.updateMLEInfo >>");
		boolean result;
		try {
			result =apiClientServices.updateMLE(ConverterUtil.getMleApiClientObject(dataVO));
		} catch (Exception e) {
                    result = false;
			log.error(e.getMessage());
			throw ConnectionUtil.handleException(e);
		}
		log.info("MLEClientServiceImpl.updateMLEInfo <<");
		return result;
	}

	/**
	 * Method to delete MLE Type from a rest services
	 * 
	 * @param dataVO
	 * @param apiClientServices
	 * @return Boolean variable e.g true if MLE is deleted successfully 
	 * @throws WLMPortalException
	 */
	@Override
	public boolean deleteMLE(MLEDataVO dataVO,WhitelistService apiClientServices) throws WLMPortalException {
		log.info("MLEClientServiceImpl.deleteMLE >>");
		boolean result = false; 
		try {
			MLESearchCriteria criteria = new MLESearchCriteria();
			criteria.mleName = dataVO.getMleName();
    	    criteria.mleVersion = dataVO.getMleVersion();
    	    if (dataVO.getOemName() != null) {
				criteria.oemName = dataVO.getOemName();
				criteria.osName = "";
				criteria.osVersion = "";
			}else {
				criteria.osName = dataVO.getOsName();
				criteria.osVersion = dataVO.getOsVersion();
				criteria.oemName = "";
			}
			result = apiClientServices.deleteMLE(criteria);
		} catch (Exception e) {
			log.error(e.getMessage());
			throw ConnectionUtil.handleException(e);
		}
       

                         log.info("MLEClientServiceImpl.deleteMLE <<");
       	return result;
	}
	
	/**
	 * Method to get Single MLE Details from a rest services.
	 * 
	 * @param dataVO
	 * @param apiClientServices
	 * @return
	 * @throws WLMPortalException
	 */
	@Override
	public MLEDataVO getSingleMleData(MLEDataVO dataVO,WhitelistService apiClientServices) throws WLMPortalException {
                        log.info("MLEClientServiceImpl.getSingleMleData >>");
                        MLEDataVO mleObject = null;
                        try {
                                MLESearchCriteria criteria = new MLESearchCriteria();
                                criteria.mleName = dataVO.getMleName();
                                criteria.mleVersion = dataVO.getMleVersion();
                                if (dataVO.getOemName() != null) {
                                        criteria.oemName = dataVO.getOemName();
                                        criteria.osName = "";
                                        criteria.osVersion = "";
                                }else{
                                        criteria.osName = dataVO.getOsName();
                                        criteria.osVersion = dataVO.getOsVersion();
                                        criteria.oemName = "";
                                }
                                mleObject = ConverterUtil.getMleDataVoObject(apiClientServices.getMLEManifest(criteria));
                        }catch (Exception e) {
                                throw ConnectionUtil.handleException(e);
                        }
                        log.info("MLEClientServiceImpl.getSingleMleData <<");
                        return mleObject;
	}
        
        /**
         * Retries the name of the host that was used for white listing the MLE.
         * 
         * @param dataVO : Object containing the details of the MLE for which the host information needs to be retrieved.
         * @param apiClientServices: ApiClient object
         * @return : Name of the host
         * @throws WLMPortalException 
         */
	@Override
	public String getMleSourceHost(MLEDataVO dataVO,WhitelistService apiClientServices) throws WLMPortalException {
                        log.info("MLEClientServiceImpl.getMleSourceHost >>");
                        String hostName;
                        try {
                                MleData mleDataObj = ConverterUtil.getMleApiClientObject(dataVO);
                                if (dataVO.getOemName() != null) {
                                        mleDataObj.setOemName(dataVO.getOemName());
                                        mleDataObj.setOsName("");
                                        mleDataObj.setOsVersion("");
                                }else{
                                        mleDataObj.setOsName(dataVO.getOsName());
                                        mleDataObj.setOsVersion(dataVO.getOsVersion());
                                        mleDataObj.setOemName("");
                                }
                                hostName = apiClientServices.getMleSource(mleDataObj);
                        }catch (Exception e) {
                                throw ConnectionUtil.handleException(e);
                        }
                        log.info("MLEClientServiceImpl.getMleSourceHost <<");
                        return hostName;
	}
        
}
