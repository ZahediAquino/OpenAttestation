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
 * This class will used to handle all request related to Getting data from REST services or saving data into REST Services. 
 */
package com.intel.mountwilson.controller;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.multiaction.MultiActionController;

import com.google.common.collect.Lists;
import com.intel.mountwilson.Service.IDemoPortalServices;
import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mountwilson.common.DemoPortalException;
import com.intel.mountwilson.common.TDPConfig;
import com.intel.mountwilson.constant.HelperConstant;
import com.intel.mountwilson.datamodel.HostDetailsEntityVO;
import com.intel.mountwilson.datamodel.HostVmMappingVO;
import com.intel.mountwilson.util.JSONView;
import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.AttestationService;
import com.intel.mtwilson.util.crypto.SimpleKeystore;
import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * @author yuvrajsx
 *
 */
public class DemoPortalDataController extends MultiActionController {
	
	// variable declaration used for Logging.  
        Logger log = LoggerFactory.getLogger(getClass().getName());
	
	//Services Layer object, used to invoke service layer methods.
	private IDemoPortalServices demoPortalServices; 
	
	public DemoPortalDataController(){
		
	}
	
	/**
	 * Method is used to get Trust Status for Hosts to show on Home Screen.
	 * 
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getDashBoardData(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getDashBoardData >>");
		Map<Integer, List<HostDetailsEntityVO>> map =null; 
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
                        boolean forceVerify = Boolean.parseBoolean(req.getParameter("force_verify"));
			//Get map view for All Host based on the value of Page_NO(this values is available from TDPConfig) 
			map = getAllHostDetailsFromDB(req);
			
			//calling into a Service layer to get trust status for Host on Page No 1(using map.get(1)).
			//responseView.addObject("hostVo",demoPortalServices.getTrustStatusForHost(map.get(1),getAttestationService(req,AttestationService.class),getTrustedCertificates(req)));
                        responseView.addObject("hostVo",demoPortalServices.getTrustStatusForHost(map.get(1),getAttestationService(req,AttestationService.class),getTrustedCertificates(req), forceVerify));
                        
                        
			
			//setting no of page required to show all Host data while applying pagination in JSP
			responseView.addObject("noOfPages", map.size());
		} catch (Exception e) {
			log.error("getDashBoardData exception: " + e.toString());
			responseView.addObject("hostVo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
                        if(e.getMessage().toLowerCase().contains("currently there are no hosts configured")) {
                            responseView.addObject("noHosts",true);
                        }
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getDashBoardData <<<");
		return responseView;
	}
	
	/**
	 * Method is used to get trust status of host for selected page no.
	 * Method will get called when user choose any page no from pagination.
	 * 
	 * @param req
	 * @param res
	 * @return
	 */
	public ModelAndView getHostTrustSatusForPageNo(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getHostTrustSatusForPageNo >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
			//getting selected Page No.
			int selectedPage = Integer.parseInt(req.getParameter("pageNo"));
                        boolean forceVerify = Boolean.parseBoolean(req.getParameter("force_verify"));
			HttpSession session = req.getSession();
			@SuppressWarnings("unchecked")
			//getting Map view of all Host stored into session while calling getDashBoardData().
			Map<Integer, List<HostDetailsEntityVO>> mapOfData  = (Map<Integer, List<HostDetailsEntityVO>>) session.getAttribute("HostVoList");
			
			//calling into a Service layer to get trust status of Host for selected Page No.
			responseView.addObject("hostVo", demoPortalServices.getTrustStatusForHost(mapOfData.get(selectedPage), getAttestationService(req,AttestationService.class),getTrustedCertificates(req), forceVerify));
			responseView.addObject("noOfPages", mapOfData.size());
		} catch (Exception e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("hostVo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getHostTrustSatusForPageNo <<");
		return responseView;
	}
	
	
	/**
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getHostTrustStatus(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getHostTrustStatus >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
                        boolean forceVerify = Boolean.parseBoolean(req.getParameter("force_verify"));
			responseView.addObject("hostVo", demoPortalServices.getSingleHostTrust(req.getParameter("hostName"),getAttestationService(req,AttestationService.class),getTrustedCertificates(req), forceVerify));
		} catch (DemoPortalException e) {
			log.error("getHostTrustStatus: " + e.toString());
			e.printStackTrace();
			responseView.addObject("hostVo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getHostTrustStatus <<<");
		return responseView;
	}
	
	/**
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getAllOemInfo(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getAllOemInfo >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
			responseView.addObject("oemInfo", demoPortalServices.getAllOemInfo(getAttestationService(req,ApiClient.class)));
		} catch (DemoPortalException e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("oemInfo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getAllOemInfo <<<");
		return responseView;
	}
	
	/**
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getOSVMMInfo(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getOSVMMInfo >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
			responseView.addObject("osInfo", demoPortalServices.getOSAndVMMInfo(getAttestationService(req,ApiClient.class)));
		} catch (DemoPortalException e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("osInfo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getOSVMMInfo <<<");
		return responseView;
	}
	
	public ModelAndView saveNewHostInfo(HttpServletRequest req,HttpServletResponse res) {
		log.info("WLMDataController.saveNewHostInfo >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		String hostObject = null;
		boolean newhost = false;
			try {
				hostObject = req.getParameter("hostObject");
				newhost = Boolean.parseBoolean(req.getParameter("newhost"));
			} catch (Exception e1) {
				responseView.addObject("result",false);
				responseView.addObject("message",e1.getMessage());
			}
		System.out.println(hostObject);
		ObjectMapper mapper = new ObjectMapper();
		HostDetailsEntityVO dataVO = new HostDetailsEntityVO();
		
		try {
			dataVO = mapper.readValue(hostObject,HostDetailsEntityVO.class);
		} catch (JsonParseException e) {
			log.error("Error While Parsing request parameters Data. "+e.getMessage());
			responseView.addObject("result",false);
			responseView.addObject("message","Error While Parsing request parameters Data.");
			return responseView;
		} catch (JsonMappingException e) {
			log.error("Error While Mapping request parameters to Mle Data Object. "+e.getMessage());
			responseView.addObject("result",false);
			responseView.addObject("message","Error While Mapping request parameters to Mle Data Object.");
			return responseView;
		} catch (IOException e) {
			log.error("IO Exception "+e.getMessage());
			responseView.addObject("result",false);
			responseView.addObject("message","Error While Mapping request parameters to Mle Data Object.");
			return responseView;
		}
		
		dataVO.setUpdatedOn(new Date(System.currentTimeMillis()));
		
		try {
			if (newhost) {
				System.err.println("dataForNew : "+dataVO);
				responseView.addObject("result",demoPortalServices.saveNewHostData(dataVO,getAttestationService(req,AttestationService.class)));
			}else {
				System.err.println("dataForOLD : "+dataVO);
				responseView.addObject("result", demoPortalServices.updateHostData(dataVO,getAttestationService(req,AttestationService.class)));
			}
		} catch (DemoPortalException e) {
			log.error(e.getMessage());
			responseView.addObject("result",false);
			responseView.addObject("message",e.getMessage());
			return responseView;
		}
		log.info("WLMDataController.saveNewHostInfo <<<");
		return responseView;
		
	}
	
	/**
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getInfoForHostID(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getInfoForHostID >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
			String hostName = req.getParameter("hostName");
			responseView.addObject("hostData", demoPortalServices.getSingleHostDetailFromDB(hostName,getAttestationService(req,AttestationService.class)));
		} catch (Exception e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("oemInfo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getInfoForHostID <<<");
		return responseView;
	}
	
	
	/**
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView deleteHostDetails(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.deleteHostDetails >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		int selectedPage ;
		try {
			selectedPage = Integer.parseInt(req.getParameter("selectedPageNo"));
			boolean updateDone = demoPortalServices.deleteHostDetails(req.getParameter("hostID"),req.getParameter("hostName"),getAttestationService(req,AttestationService.class));
			if (updateDone) {
				Map<Integer, List<HostDetailsEntityVO>> mapOfData = getAllHostDetailsFromDB(req);
				
				if (selectedPage > mapOfData.size()) {
					selectedPage = mapOfData.size();
				}
				responseView.addObject("hostVo", mapOfData.get(selectedPage));
				responseView.addObject("noOfPages", mapOfData.size());
				responseView.addObject("result",updateDone);
			}else {
				log.error("Error Wile deleting OS Data. Server Error.");
				responseView.addObject("result",false);
				responseView.addObject("message","Api Client return false.");
			}
		} catch (DemoPortalException e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.deleteHostDetails<<<");
		return responseView;
	}
		
	
	/**
	 * Method to get Host list to for View Host page.
	 * 
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getAllHostForView(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getAllHostForView >>");
		Map<Integer, List<HostDetailsEntityVO>> map =null; 
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
			map = getAllHostDetailsFromDB(req);
			
			responseView.addObject("hostVo",map.get(1));
			responseView.addObject("noOfPages", map.size());
		} catch (DemoPortalException e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("hostVo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getAllHostForView<<<");
		return responseView;
	}
	
	/**
	 * Method to get Host list to for View Host Page for given page no.
	 * 
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getHostForViewForPage(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getHostForViewForPage >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
			int selectedPage = Integer.parseInt(req.getParameter("pageNo"));
			HttpSession session = req.getSession();
			@SuppressWarnings("unchecked")
			Map<Integer, List<HostDetailsEntityVO>> mapOfData  = (Map<Integer, List<HostDetailsEntityVO>>) session.getAttribute("HostVoList");
			responseView.addObject("hostVo", mapOfData.get(selectedPage));
		} catch (Exception e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("hostVo", "");
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("result", true);
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getHostForViewForPage<<<");
		return responseView;
	}
	
	
	/**
	 * Method to get Trust Verification Details using SAML.
	 * 
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView trustVerificationDetailsXML(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.trustVerificationDetailsXML >>");
                ModelAndView responseView = new ModelAndView(new JSONView());
                String hostName = req.getParameter("hostName");
		try {
			responseView.addObject("trustSamlDetails", demoPortalServices.trustVerificationDetails(hostName,getAttestationService(req,AttestationService.class),getTrustedCertificates(req)));
			responseView.addObject("hostName", hostName);
			responseView.addObject("result", true);
		} catch (DemoPortalException e) {
			log.error(e.toString());
			e.printStackTrace();
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			e.printStackTrace();
			return responseView;
		}
		responseView.addObject("message", "");
		responseView.addObject("result", true);
        return responseView;
	}
	
      
	/**
	 * Method to Bulk Update trust status for selected host.
	 * 
	 * @param req (HttpServletRequest Object)
	 * @param res (HttpServletResponse Object)
	 * @return
	 */
	public ModelAndView getHostsReport(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getHostsReport >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
                String[] list = req.getParameterValues("selectedHost");
                if(list == null) {
                    responseView.addObject("message", "No hosts were selected for reports.");
                    log.info("DemoPortalDataController.getHostsReport<<<");
                    return responseView;
                }
		List<String> hosts = Arrays.asList(list);
		try {
			responseView.addObject("reports", demoPortalServices.getHostTrustReport(hosts,getAttestationService(req,ApiClient.class)));
			responseView.addObject("result", true);
		} catch (DemoPortalException e) {
			log.error(e.getMessage());
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getHostsReport<<<");
		return responseView;
	}
        
    public ModelAndView logOutUser(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.logOutUser >>");
		ModelAndView responseView = new ModelAndView("Login");
		try {
			HttpSession session = req.getSession(false);
            if (session != null) {
                session.invalidate();
            }
		} catch (Exception e) {
			log.error( e.toString());
			e.printStackTrace();
		}
		log.info("DemoPortalDataController.logOutUser <<");
		return responseView;
	}
	
	
	public ModelAndView getFailurereportForHost(HttpServletRequest req,HttpServletResponse res) {
		log.info("DemoPortalDataController.getFailurereportForHost >>");
		ModelAndView responseView = new ModelAndView(new JSONView());
		try {
			responseView.addObject("reportdata", demoPortalServices.getFailureReportData(req.getParameter("hostName"),getAttestationService(req,ApiClient.class)));
			responseView.addObject("result", true);
		} catch (Exception e) {
			log.error(e.getMessage());
			responseView.addObject("result", false);
			responseView.addObject("message", e.getMessage());
			return responseView;
		}
		responseView.addObject("message", "");
		log.info("DemoPortalDataController.getFailurereportForHost <<");
		return responseView;
	}
	
	public void setDemoPortalServices(IDemoPortalServices demoPortalServices){
		this.demoPortalServices = demoPortalServices;
	}
	
	/**
	 * This method is used as a utility method to get Map Views for all host based on Page_no value.
	 * 
	 * @param req
	 * @return Map<Integer, List<HostDetailsEntityVO>> 
	 * @throws DemoPortalException
	 */
	private Map<Integer, List<HostDetailsEntityVO>> getAllHostDetailsFromDB(HttpServletRequest req) throws DemoPortalException {
		Map<Integer, List<HostDetailsEntityVO>> map =new HashMap<Integer, List<HostDetailsEntityVO>>();
		
		//Get List of all host available. 
		List<HostDetailsEntityVO> listOfVos = demoPortalServices.getHostListFromDB(getAttestationService(req,AttestationService.class));
		int no_row_per_page = Integer.parseInt(TDPConfig.getConfiguration().getString("mtwilson.tdbp.paginationRowCount"));
		
		//Divide List of all host into a subList based on the value of host per page. 
		List<List<HostDetailsEntityVO>> list = Lists.partition(listOfVos, no_row_per_page);
		
		//Creating a Map view of host list based on the Page No.
		int i=1;
		for (List<HostDetailsEntityVO> listForMap : list) {
			map.put(i, listForMap);
			i++;
		}
		
		//setting map into session attribute;
		HttpSession session = req.getSession();
		session.setAttribute("HostVoList", map);
		return map;
	}
	
    /**
     * This method will return a AttestationService/ApiClient Object from a Session.
     * This object is stored into Session at time of user login.
     * Check CheckLoginController.java for more Clarification.
     * 
     * @param req
     * @return 
     * @return AttestationService
     * @throws DemoPortalException
     */
    @SuppressWarnings("unchecked")
	private <T> T getAttestationService(HttpServletRequest req,Class<T> type) throws DemoPortalException{
        
    	//getting already created session object by passing false while calling into getSession();
    	HttpSession session = req.getSession(false);
        T service = null;
        if(session !=null){
            try{
            	
            	//getting ApiClient Object from Session and downcast that object to Type T.  
                service = (T) session.getAttribute("apiClientObject");    
            } catch (Exception e) {
				log.error("Error while creating ApiCliennt Object. "+e.getMessage());
				throw new DemoPortalException("Error while creating ApiCliennt Object. "+e.getMessage(),e);
            }
            
        }
        return service;
     }
        
    /**
     * This method will return a X509Certificate Object from a Request Session.
     * This object is stored into Session at time of user login.
     * Check CheckLoginController.java for more Clarification.
     * 
     * @param req
     * @return
     * @throws DemoPortalException
     */
    private X509Certificate[] getTrustedCertificates(HttpServletRequest req) throws DemoPortalException{
    	HttpSession session = req.getSession(false);
    	X509Certificate[] trustedCertificate;
    	if(session !=null){
    		try{
    			//getting Object from Session and downcast that object to X509Certificate. 
    			trustedCertificate = (X509Certificate[])session.getAttribute("trustedCertificates");
                        
    		} catch (Exception e) {
    			log.error("Error while creating ApiCliennt Object. "+e.getMessage());
    			throw new DemoPortalException("Error while creating ApiCliennt Object. "+e.getMessage(),e);
    		}
    		
    	}else{
    		return null;
    	}
    	return trustedCertificate;
    }
        
}
