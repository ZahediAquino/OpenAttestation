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
 * 
 */
package com.intel.mountwilson.Service;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import com.intel.mountwilson.common.DemoPortalException;
import com.intel.mountwilson.datamodel.HostDetailsEntityVO;
import com.intel.mountwilson.datamodel.HostReportTypeVO;
import com.intel.mountwilson.datamodel.HostVmMappingVO;
import com.intel.mountwilson.datamodel.TrustedHostVO;
import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.AttestationService;
import com.intel.mtwilson.datatypes.PcrLogReport;

/**
 * @author yuvrajsx
 *
 */
public interface IDemoPortalServices {

	/**
	 * @param hostList
	 * @param apiClientServices
	 * @param trustedCertificates
	 * @return
	 * @throws DemoPortalException
	 */
	public List<TrustedHostVO> getTrustStatusForHost(List<HostDetailsEntityVO> hostList,AttestationService apiClientServices,X509Certificate[] trustedCertificates, boolean forceVerify) throws DemoPortalException;

	/**
	 * @param hostName
	 * @param apiClientServices
	 * @param trustedCertificates
	 * @return
	 * @throws DemoPortalException
	 */
	public TrustedHostVO getSingleHostTrust(String hostName,AttestationService apiClientServices, X509Certificate[] trustedCertificates, boolean forceVerify) throws DemoPortalException;

	/**
	 * @param client
	 * @return
	 * @throws DemoPortalException
	 */
	Map<String, List<Map<String, String>>> getAllOemInfo(ApiClient client)	throws DemoPortalException;

	/**
	 * @param client
	 * @return
	 * @throws DemoPortalException
	 */
	Map<String, Boolean> getOSAndVMMInfo(ApiClient client) throws DemoPortalException;

	/**
	 * @param dataVO
	 * @param apiClientServices
	 * @return
	 * @throws DemoPortalException
	 */
	public boolean saveNewHostData(HostDetailsEntityVO dataVO, AttestationService apiClientServices) throws DemoPortalException;

	/**
	 * @param dataVO
	 * @param apiClientServices
	 * @return
	 * @throws DemoPortalException
	 */
	public boolean updateHostData(HostDetailsEntityVO dataVO, AttestationService apiClientServices)throws DemoPortalException;

	/**
	 * @param hostID
	 * @param hostName
	 * @param apiClientServices
	 * @param vmMappingData
	 * @return
	 * @throws DemoPortalException
	 */
	public boolean deleteHostDetails(String hostID, String hostName,AttestationService apiClientServices)throws DemoPortalException;

	/**
	 * @param service
	 * @return
	 * @throws DemoPortalException
	 */
	List<HostDetailsEntityVO> getHostListFromDB(AttestationService service) throws DemoPortalException;
	
	HostDetailsEntityVO getSingleHostDetailFromDB(String hostName, AttestationService service) throws DemoPortalException;

	/**
	 * @param hostName
	 * @param apiClientServices
	 * @param trustedCertificates
	 * @return
	 * @throws DemoPortalException
	 */
	String trustVerificationDetails(String hostName,AttestationService apiClientServices,X509Certificate[] trustedCertificates) throws DemoPortalException;
        
    public List<HostReportTypeVO> getHostTrustReport(List<String> hostNames,ApiClient client)throws DemoPortalException;

	/**
	 * This method is used to get failure report for Host.
	 * 
	 * @param hostName
	 * @param attestationService
	 * @return
	 * @throws DemoPortalException
	 * @throws Exception
	 */
	public List<PcrLogReport> getFailureReportData(String hostName,ApiClient attestationService) throws DemoPortalException, Exception;
}
