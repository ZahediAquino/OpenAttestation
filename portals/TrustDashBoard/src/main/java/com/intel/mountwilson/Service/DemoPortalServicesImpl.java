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
 * This Class contains methods used to communicate to REST Services.
 */
package com.intel.mountwilson.Service;

import com.intel.mountwilson.as.hosttrustreport.data.HostType;
import com.intel.mountwilson.as.hosttrustreport.data.HostsTrustReportType;
import com.intel.mountwilson.common.DemoPortalException;
import com.intel.mountwilson.constant.HelperConstant;
import com.intel.mountwilson.datamodel.HostDetailsEntityVO;
import com.intel.mountwilson.datamodel.HostReportTypeVO;
import com.intel.mountwilson.datamodel.MleDetailsEntityVO;
import com.intel.mountwilson.datamodel.TrustedHostVO;
import com.intel.mountwilson.util.ConnectionUtil;
import com.intel.mountwilson.util.ConverterUtil;
import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.AttestationService;
import com.intel.mtwilson.WhitelistService;
import com.intel.mtwilson.datatypes.AttestationReport;
import com.intel.mtwilson.datatypes.HostTrustResponse;
import com.intel.mtwilson.util.net.Hostname;
import com.intel.mtwilson.datatypes.PcrLogReport;
import com.intel.mtwilson.datatypes.TxtHostRecord;
import com.intel.mtwilson.datatypes.xml.HostTrustXmlResponse;
import com.intel.mtwilson.saml.TrustAssertion;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import com.intel.mtwilson.ApiException;
import com.intel.mtwilson.saml.TrustAssertion.HostTrustAssertion;
import java.security.SignatureException;

/**
 * @author yuvrajsx
 *
 */
public class DemoPortalServicesImpl implements IDemoPortalServices {
	
	//Variable used for logging. 
        Logger log = LoggerFactory.getLogger(getClass().getName());
	
	//variable used to change date into given format to display on screen.  
	private static final DateFormat formatter=  new SimpleDateFormat("MM/dd/yyyy hh:mm:ss");
	
	
	/**
	 * This method is used to get host trust status from REST services and convert that data into TrustedHostVO Object.
	 * 
	 * @param hostList (List contains all Host information for which trust status is needed.)
	 * @param apiClientServices
	 * @param trustedCertificates
	 * @return List of TrustedHostVO Objects.
	 * @throws DemoPortalException
	 */
	@Override
	public List<TrustedHostVO> getTrustStatusForHost(List<HostDetailsEntityVO> hostList, AttestationService apiClientServices,X509Certificate[] trustedCertificates, boolean forceVerify) throws DemoPortalException {
                                //List contains data to be return.
                                List<TrustedHostVO> hostVOs = new ArrayList<TrustedHostVO>();

                                //check size of List of Host for which Trust is required if its empty Throw Exception with specific message to Controller.
                                if (hostList!=null && hostList.size() > 0) {
                                        for (HostDetailsEntityVO hostDetailsEntityVO : hostList) {
                                            hostVOs.add(getSingleHostTrust(hostDetailsEntityVO.getHostName(), apiClientServices, trustedCertificates, forceVerify));
                                        }
			
                                } else {
                                        throw new DemoPortalException("Currently there are no hosts configured in the system.");
                                }
                                
                                return hostVOs;
                        }
	
	/**
	 * This Method will get all configured Host Details from REST Services.
	 * 
	 * @param service (Object of AttestationService, used to call into REST Services)
	 * @return List of HostDetailsEntityVO Objects
	 * @throws DemoPortalException
	 */
	@Override
	public List<HostDetailsEntityVO> getHostListFromDB(AttestationService service) throws DemoPortalException{
		List<HostDetailsEntityVO> hostList  = null;
		try{
			//Call into REST Services for getting all HOST information by passing empty String.
			hostList = ConverterUtil.getHostVOListFromTxtHostRecord(service.queryForHosts("")); 
		} catch (Exception e) {
			log.error("Error While getting data from DataBase."+e.getMessage());	
			 throw ConnectionUtil.handleException(e);
		}
		
		//Check if Return list is empty or Not, if empty throw Exception to controller with Specific message. 
		if (hostList==null || hostList.size() < 0) {
			throw new DemoPortalException("Currently there are no hosts configured in the system.");
		}
		
		//Statements to change data according to need, replace all null values with Empty String so it will not shown up on screen.
		for (HostDetailsEntityVO hostDetailsEntityVO : hostList) {
			//System.out.println(hostDetailsEntityVO);
			
			if (hostDetailsEntityVO.getvCenterDetails() == null || hostDetailsEntityVO.getvCenterDetails().equals("null")) {
				hostDetailsEntityVO.setvCenterDetails("");
				//If vCenter String is present then remove Administrator and password from it while returning.
            	}else if(hostDetailsEntityVO.getvCenterDetails().indexOf(";") >= 0){
                      String vCenterString =  hostDetailsEntityVO.getvCenterDetails().substring(0, hostDetailsEntityVO.getvCenterDetails().indexOf(";"));
                      hostDetailsEntityVO.setvCenterDetails(vCenterString);
                  }
				
			if(hostDetailsEntityVO.getHostIPAddress() == null || hostDetailsEntityVO.getHostIPAddress().equals("null")){
				hostDetailsEntityVO.setHostIPAddress("");
			}
			if(hostDetailsEntityVO.getHostPort() == null || hostDetailsEntityVO.getHostPort().equals("null")){
				hostDetailsEntityVO.setHostPort("");
			}
			if(hostDetailsEntityVO.getEmailAddress() == null || hostDetailsEntityVO.getEmailAddress().equals("null")){
				hostDetailsEntityVO.setEmailAddress("");
			}
			if(hostDetailsEntityVO.getvCenterDetails() == null || hostDetailsEntityVO.getvCenterDetails().equals("null")){
				hostDetailsEntityVO.setvCenterDetails("");
			}
			if(hostDetailsEntityVO.getHostDescription() == null || hostDetailsEntityVO.getHostDescription().equals("null")){
				hostDetailsEntityVO.setHostDescription("");
			}
		}
		return hostList;
	}
	
	/**
	 * This Method is used to get Trust Status for Single Host.
	 * 
	 * @param hostName
	 * @param apiClientServices
	 * @param trustedCertificates
	 * @return
	 * @throws DemoPortalException
	 */
	@Override
	public TrustedHostVO getSingleHostTrust(String hostName, AttestationService apiClientServices,X509Certificate[] trustedCertificates, boolean forceVerify)throws DemoPortalException {
		
		TrustedHostVO hostVO = null;
	           HostDetailsEntityVO hostDetailsEntityVO = new HostDetailsEntityVO();
            hostDetailsEntityVO.setHostName(hostName);
            String xmloutput = null;

            HostTrustResponse hostTrustResponse = null;
            try {
                log.info("Getting trust Information for Host " + hostName);
		//xmloutput = apiClientServices.getSamlForHost(new Hostname(hostName), false);
                // forceVerify=false when loading dashboard, it is true when refreshing host (Refresh button)
                xmloutput = apiClientServices.getSamlForHost(new Hostname(hostName), forceVerify);
                
                TrustAssertion trustAssertion = new TrustAssertion(trustedCertificates, xmloutput);
                HostTrustAssertion hostTrustAssertion = trustAssertion.getTrustAssertion(hostName);  
		
                //Set<Hostname> hostnames = new HashSet<Hostname>();
                //hostnames.add(new Hostname(hostName));
                //xmloutput = ConverterUtil.formateXMLString(apiClientServices.getSamlForMultipleHosts(hostnames, false));
                
                hostTrustResponse = apiClientServices.getHostTrust(new Hostname(hostDetailsEntityVO.getHostName()));
                List<TxtHostRecord> hosts = apiClientServices.queryForHosts(hostDetailsEntityVO.getHostName());
                TxtHostRecord txtHostRecord = null;
                for (TxtHostRecord record : hosts) {
                    if (record.HostName.equals(hostDetailsEntityVO.getHostName())) {
                        txtHostRecord = record;
                    }
                }
                hostVO = ConverterUtil.getTrustedHostVoFromHostTrustResponseAndTxtHostRecord(hostTrustResponse, txtHostRecord, hostTrustAssertion);
            } catch (Exception e) {

                hostVO = ConverterUtil.getTrustedHostVoFromHostTrustResponseAndErrorMessage(hostName, e.getMessage());
            }

            return hostVO;
	}
	
	/**
	 * This method is used to get all OEM details from REST Services.
	 * Call to searchMLE method present in ApiClient class by passing empty string as parameter. this Method will return all MLE from services.
	 * 
	 * @param client (Object of ApiClient)
	 * @return
	 * @throws DemoPortalException
	 */
	@Override
	public Map<String, List<Map<String, String>>> getAllOemInfo(ApiClient client)throws DemoPortalException {
		
		Map<String, List<Map<String, String>>> map = new HashMap<String, List<Map<String,String>>>();
		List<MleDetailsEntityVO> mleList = null;
        List<Map<String, String>> list = new ArrayList<Map<String,String>>();
		
		try {
			WhitelistService service = (WhitelistService) client;
			//This statement will get all MLE information from REST services, will get only OEM information from that list.
			 mleList = ConverterUtil.getMleVOListWhereOEMNotNull(service.searchMLE(""));
			
			 //convert data into a MAP of Strings which is used in UI (JQuery) to display on screen.
			 if (mleList != null && mleList.size() > 0) {
				for (MleDetailsEntityVO mleDetailsEntityVO : mleList) {
					if (map.get(mleDetailsEntityVO.getOemName()) == null) {
						list = new ArrayList<Map<String,String>>();
						map.put(mleDetailsEntityVO.getOemName(), list);
					}else {
						list = map.get(mleDetailsEntityVO.getOemName());
					}
					Map<String, String> oemInfo = new HashMap<String, String>();
					oemInfo.put(mleDetailsEntityVO.getMleName(), mleDetailsEntityVO.getMleVersion());
					list.add(oemInfo);
				}
			}else {
				throw new DemoPortalException("Currently no MLEs are configured in the system.");                                
			}
		}catch (Exception e) {
			throw ConnectionUtil.handleException(e);
		}
		return map;
	}
	
	/**
	 * This method is used to Get All OS details from REST Services.
	 * 
	 * @param client (Object of ApiClient)
	 * @return
	 * @throws DemoPortalException
	 */
	@Override
	public Map<String, Boolean> getOSAndVMMInfo(ApiClient client)throws DemoPortalException {
		 List<MleDetailsEntityVO> mleList = null;
		 //This is a MAP of OS/VMM name and boolean variable which denote about current os/vmm info is VMWare type or not. 
		 Map<String,Boolean> maps = new HashMap<String, Boolean>();
		 WhitelistService service = (WhitelistService) client;
		try {
			//Call to REST Services to get all details of MLE, will extract all MLE from that data where OEM info is null.
			mleList = ConverterUtil.getMleVOListWhereOEMIsNull(service.searchMLE(""));
	        for (MleDetailsEntityVO mleDetailsEntityVO : mleList) {
	        	maps.put(ConverterUtil.getOSAndVMMInfoString(mleDetailsEntityVO), mleDetailsEntityVO.getOsName().toLowerCase().contains(HelperConstant.OS_IMAGE_VMWARE.toLowerCase()) ? true : false);
			}
		}
		catch (Exception e) {
			 throw ConnectionUtil.handleException(e);
		}
		return maps;
	}

	/**
	 * This method is used to add/configure new Host to REST services.
	 * 
	 * @param dataVO
	 * @param apiClientServices
	 * @return
	 * @throws DemoPortalException
	 */
	@Override
	public boolean saveNewHostData(HostDetailsEntityVO dataVO,AttestationService apiClientServices)throws DemoPortalException {
		boolean result = false;
		try {
			//Call to REST Services to add host information.
			apiClientServices.addHost(ConverterUtil.getTxtHostFromHostVO(dataVO));
			result = true;
		} catch (Exception e) {
			log.error("Errror While Adding New Host."+e.getMessage());
			throw ConnectionUtil.handleException(e); 
		}
		return result;
	}
	
	/**
	 * This method is used to Update Host information, which was already configure.
	 * 
	 * @param dataVO
	 * @param apiClientServices
	 * @return
	 * @throws DemoPortalException
	 */
	@Override
	public boolean updateHostData(HostDetailsEntityVO dataVO,AttestationService apiClientServices)throws DemoPortalException {
		boolean result = false;
		try {
			//Call to Services to Update pre-configure host information.
			apiClientServices.updateHost(ConverterUtil.getTxtHostFromHostVO(dataVO));
                        // Updating the SAML host report
                        apiClientServices.getSamlForHost(new Hostname(dataVO.getHostName()), true);
			result = true;
		} catch (Exception e) {
			log.error("Errror While Updating Host.");
			throw ConnectionUtil.handleException(e);
		}
		
		return result;
	}

	/**
	 * This method will delete HOST information from Services.
	 * Also it will delete all entry from HOST VM Mapping information for that host, which is used to store Policy of VM.  
	 * 
	 * @param hostID
	 * @param hostName
	 * @param apiClientServices
	 * @param vmMappingData
	 * @return
	 * @throws DemoPortalException
	 */
	@Override
	public boolean deleteHostDetails(String hostID, String hostName,AttestationService apiClientServices) throws DemoPortalException {
		boolean result = false;
		try {
			//Call to Services to delete HOST.
			apiClientServices.deleteHost(new Hostname(hostName));
			
			result = true;
		} catch (Exception e) {
			log.error("Errror While Deleting Host.");
			 throw ConnectionUtil.handleException(e);
		}
		return result;
	}

	/**
	 * This method is used to get SAML Assertion data for a Host.
	 * This data is shown in pop-up window when user click on trust details button in Home page to TrustDashBoard.
	 * 
	 * @param hostName
	 * @param apiClientServices
	 * @param trustedCertificates
	 * @return
	 * @throws DemoPortalException
     * @throws java.io.IOException
     * @throws com.intel.mtwilson.ApiException
	 */
	@Override
	public String trustVerificationDetails(String hostName,AttestationService apiClientServices,X509Certificate[] trustedCertificates)throws DemoPortalException{
        //return ConverterUtil.formateXMLString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<error>Not implemented</error>\n");
        
        Set<Hostname> hostnames = new HashSet<Hostname>();
        hostnames.add(new Hostname(hostName));
        try{
            return ConverterUtil.formateXMLString(apiClientServices.getSamlForMultipleHosts(hostnames, true));
        }
        catch(IOException | ApiException | SignatureException e){
            log.error(e.getMessage());
            return ConverterUtil.formateXMLString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<error>Not implemented</error>\n");
        }
        
//        log.info("DemoPortalServicesImpl.trustVerificationDetails >>");
//	    String xmloutput = null;
//            Set<Hostname> hostnames = new HashSet<Hostname>();
//            //log.info("<<<<<<Hostname: " + hostName + ">>>>>>>");
//            hostnames.add(new Hostname(hostName));
//            try {
//                //calling into Services to get SAML for a Host.
//                List<HostTrustXmlResponse> trust = apiClientServices.getSamlForMultipleHosts(hostnames, false);
//
//                for (HostTrustXmlResponse hostTrustXmlResponse : trust) {
//                    if(trustedCertificates != null)
//                        log.info("TrustCertificates: " + trustedCertificates.toString());
//                    else
//                        log.info("TrustCertificates is null");
//                    if(hostTrustXmlResponse != null)
//                        log.info("HostTrustXMLResponse: " + hostTrustXmlResponse.getAssertion());
//                    else
//                        log.info("HostTrustXMLResponse is null");
//                    
//                    TrustAssertion trustAssertion = new TrustAssertion(trustedCertificates, hostTrustXmlResponse.getAssertion());
//                    
//                    if(trustAssertion != null)
//                        log.info("TrustAssertion: " + trustAssertion.toString());
//                    else
//                        log.info("TrustAssertion is null");
//                    if (trustAssertion.isValid()) {
//                        //Store SAML Assertion into a String.
//                        xmloutput = hostTrustXmlResponse.getAssertion();
//                    } else {
//                        log.error("Error While Getting SAML ." + hostTrustXmlResponse.getErrorCode() + ". " + hostTrustXmlResponse.getErrorMessage());
//                        throw new DemoPortalException("Error While Getting SAML. " + hostTrustXmlResponse.getErrorCode() + ". " + hostTrustXmlResponse.getErrorMessage());
//                    }
//                }
//            } catch (Exception e) {
//                log.error(e.getMessage());
//                e.printStackTrace();
//                throw ConnectionUtil.handleDemoPortalException(e);
//            }
            //format a SAML String into a XML type using helper Function.
//            return ConverterUtil.formateXMLString(xmloutput);
	}
	
        
        
   	@Override
	public List<HostReportTypeVO> getHostTrustReport(List<String> hostNames,ApiClient client)throws DemoPortalException {
		
                                AttestationService service = (AttestationService) client;
                                HostsTrustReportType report = null;
                                List<HostReportTypeVO> hostReportTypeVO = new ArrayList<HostReportTypeVO>();
                                        try {
                                List<Hostname> hostList = new ArrayList<Hostname>();
                                for (String host : hostNames) {
                                        hostList.add(new Hostname(host));
                                }
                                report = service.getHostTrustReport(hostList);
                                        } catch (Exception e) {
                                                log.error(e.getMessage());
                                                throw  ConnectionUtil.handleException(e);
                                        }

                                        List<HostType> list = report.getHost();

                                        for (HostType hostType : list) {
                                        HostReportTypeVO vo = new HostReportTypeVO();
                                        vo.setHostName(hostType.getHostName());
                                        vo.setMleInfo(hostType.getMLEInfo());
                                        vo.setCreatedOn("");
                                        vo.setTrustStatus(hostType.getTrustStatus());
                                        vo.setVerifiedOn(formatter.format(hostType.getVerifiedOn().toGregorianCalendar().getTime()));
                                        hostReportTypeVO.add(vo);
                                        }
		return hostReportTypeVO;
	}
    
    
	@Override
	public HostDetailsEntityVO getSingleHostDetailFromDB(String hostName,AttestationService service) throws DemoPortalException {
		//HostDetailsEntityVO hostDetailsEntityVO  = new HostDetailsEntityVO();
            HostDetailsEntityVO hostDetailsEntityVO;
		try{
			hostDetailsEntityVO = ConverterUtil.getHostVOObjectFromTxtHostRecord(service.queryForHosts(hostName).get(0));
		} catch (Exception e) {
			log.error("Error While getting data from DataBase."+e.getMessage());
			 throw ConnectionUtil.handleException(e);
		}
    	
		
                                        if(hostDetailsEntityVO.getHostIPAddress() == null || hostDetailsEntityVO.getHostIPAddress().equals("null")){
                                                hostDetailsEntityVO.setHostIPAddress("");
                                        }
                                        if(hostDetailsEntityVO.getHostPort() == null || hostDetailsEntityVO.getHostPort().equals("null")){
                                                hostDetailsEntityVO.setHostPort("");
                                        }
                                        if(hostDetailsEntityVO.getEmailAddress() == null || hostDetailsEntityVO.getEmailAddress().equals("null")){
                                                hostDetailsEntityVO.setEmailAddress("");
                                        }
                                        if(hostDetailsEntityVO.getvCenterDetails() == null || hostDetailsEntityVO.getvCenterDetails().equals("null")){
                                                hostDetailsEntityVO.setvCenterDetails("");
                                        }
                                        if(hostDetailsEntityVO.getHostDescription() == null || hostDetailsEntityVO.getHostDescription().equals("null")){
                                                hostDetailsEntityVO.setHostDescription("");
                                        }

                                                return hostDetailsEntityVO;
	}
	
	/**
	 * This method is used to get failure report for Host. 
	 * 
	 * @param hostName
	 * @param attestationService
	 * @return
	 * @throws DemoPortalException
	 * @throws Exception
	 */
	@Override
	public List<PcrLogReport> getFailureReportData(String hostName,ApiClient attestationService) throws Exception {
		log.info("DemoPortalServicesImpl.getFailureReportData >>");
		
			AttestationReport report;
			try {
				report = attestationService.getAttestationReport(new Hostname(hostName));
				
			} catch (Exception e) {
				log.error(e.getMessage());
				 throw ConnectionUtil.handleException(e);
			}
		
		return report.getPcrLogs();
	}
}
