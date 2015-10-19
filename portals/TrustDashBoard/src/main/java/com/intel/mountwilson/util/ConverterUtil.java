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
package com.intel.mountwilson.util;

import com.intel.mountwilson.common.TDPConfig;
import com.intel.mountwilson.constant.HelperConstant;
import com.intel.mountwilson.datamodel.HostDetailsEntityVO;
import com.intel.mountwilson.datamodel.HostType;
import com.intel.mountwilson.datamodel.HostType.hostOS;
import com.intel.mountwilson.datamodel.HostType.hostVMM;
import com.intel.mountwilson.datamodel.MleDetailsEntityVO;
import com.intel.mountwilson.datamodel.TrustedHostVO;
import com.intel.mtwilson.datatypes.HostTrustResponse;
import com.intel.mtwilson.datatypes.MleData;
import com.intel.mtwilson.datatypes.TxtHost;
import com.intel.mtwilson.datatypes.TxtHostRecord;
import com.intel.mtwilson.saml.TrustAssertion;
import java.io.StringReader;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @author yuvrajsx
 *
 */
public class ConverterUtil {
	//variable used to change date into given format to display on screen.
	//private static final DateFormat formatter=  new SimpleDateFormat("MM/dd/yyyy hh:mm:ss");
	
    
	public static String getOSAndVMMInfoString(MleDetailsEntityVO mleObject){
		return mleObject.getOsName()+HelperConstant.OS_VERSION_INFORMATION_SEPERATOR+mleObject.getOsVersion()+HelperConstant.OS_VMM_INFORMATION_SEPERATOR+mleObject.getMleName()+":"+mleObject.getMleVersion();
	}

	public static TxtHost getTxtHostFromHostVO(HostDetailsEntityVO dataVO) {
		TxtHostRecord hostRecord = new TxtHostRecord();
		hostRecord.AddOn_Connection_String = dataVO.getvCenterDetails();
		hostRecord.BIOS_Name = dataVO.getBiosName();
		hostRecord.BIOS_Oem=dataVO.getOemName();
		hostRecord.BIOS_Version=dataVO.getBiosBuildNo();
		hostRecord.Description=dataVO.getHostDescription();
		hostRecord.Email=dataVO.getEmailAddress();
		hostRecord.HostName=dataVO.getHostName();
		hostRecord.IPAddress=dataVO.getHostIPAddress();
		hostRecord.Port=Integer.parseInt(dataVO.getHostPort());
		
		String[] osVMMInfo = dataVO.getVmmName().split(Pattern.quote(HelperConstant.OS_VMM_INFORMATION_SEPERATOR));
		String osNameWithVer = osVMMInfo[0];
                String[] s = osNameWithVer.split(HelperConstant.OS_VERSION_INFORMATION_SEPERATOR);
		String osName =  s[0];
		String osVer = "";
		
		if (s.length == 2) {
			osVer = s[1];
		}else {
			for (int i = 1; i < s.length; i++) {
				osVer+=s[i]+" ";
			}
		}
		
		String hypervisor = osVMMInfo[1];
		
		hostRecord.VMM_Name=hypervisor;
		hostRecord.VMM_OSName=osName;
		hostRecord.VMM_OSVersion=osVer;
		hostRecord.VMM_Version=dataVO.getVmmBuildNo();
		return new TxtHost(hostRecord);
	}

    public static TrustedHostVO getTrustedHostVoFromHostTrustResponseAndErrorMessage(String hostName, String errorMessage) {
		TrustedHostVO hostVO = new TrustedHostVO();
        
            hostVO.setHostName(hostName);
			hostVO.setBiosStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_UNKNOWN));
			hostVO.setVmmStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_UNKNOWN));
			hostVO.setOverAllStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_UNKNOWN));
			hostVO.setOverAllStatusBoolean(false);
			hostVO.setErrorMessage(errorMessage);
                        // Bug: 445 - To shown the updated date when the host is in the unknown state
                        hostVO.setUpdatedOn(new SimpleDateFormat("EEE MMM d HH:MM:ss z yyyy").format(new Date()));
                        hostVO.setErrorCode(1);                        
        
        return hostVO;
    }
	public static TrustedHostVO getTrustedHostVoFromHostTrustResponseAndTxtHostRecord(HostTrustResponse hostTrustResponse, TxtHostRecord txtHostRecord, TrustAssertion.HostTrustAssertion hostTrustAssertion) {
		TrustedHostVO hostVO = new TrustedHostVO();
		hostVO.setHostName(hostTrustResponse.hostname.toString());
        if( hostTrustResponse.trust.bios ) {
            hostVO.setBiosStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_TRUE));
        }
        else {
            hostVO.setBiosStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_FALSE));
        }
        if( hostTrustResponse.trust.vmm ) {
				hostVO.setVmmStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_TRUE));
        }
        else {
				hostVO.setVmmStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_FALSE));
        }
        if( hostTrustResponse.trust.asset_tag ) {
				hostVO.setAssetTagStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_TRUE));
                                
                                // We will get the asset tag specific attributes here 
                                StringBuilder atdBuilder = new StringBuilder();
                                Set<String> attributeNames = hostTrustAssertion.getAttributeNames();
                                for(String attrName : attributeNames) {
                                    if(attrName.startsWith("ATAG") && !attrName.contains("UUID")) {
                                        atdBuilder.append(hostTrustAssertion.getStringAttribute(attrName) + "\n");
                                    }
                                }
                                hostVO.setAssetTagDetails(atdBuilder.toString());
        }
        else {
				hostVO.setAssetTagStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_FALSE));
                                hostVO.setAssetTagDetails("Un-Trusted");
        }
        if( hostTrustResponse.trust.bios && hostTrustResponse.trust.vmm /*&& hostTrustResponse.trust.asset_tag*/) {
				hostVO.setOverAllStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_TRUE));
				hostVO.setOverAllStatusBoolean(true);
        }
        else {
				hostVO.setOverAllStatus(TDPConfig.getConfiguration().getString(HelperConstant.IMAGE_TRUSTED_FALSE));
				hostVO.setOverAllStatusBoolean(false);
        }
        
        doMoreThingsWithHostVmmName(hostVO, txtHostRecord);
        
        // current json api does not return the timestamp of the latest trust status, so instead we implement fix for bug #445 and show the current time
        // Bug: 457 - Refresh button is not updating the time stamp
//         hostVO.setUpdatedOn(null);  
        // Bug: 445 - To shown the updated date when the host is in the unknown state
        hostVO.setUpdatedOn(new SimpleDateFormat("EEE MMM d HH:MM:ss z yyyy").format(new Date()));
        
        return hostVO;
    }
            
    public static void doMoreThingsWithHostVmmName(TrustedHostVO hostVO, TxtHostRecord txtHostRecord) {
			hostVO.setLocation(txtHostRecord.Location);
            boolean skipAddingVMMImage = false; // We will use this flag for VMware and Citrix XenServer for which there is no separate OS & VMM.
			
			//Setting up a Image for os and hypervisor
			String s = txtHostRecord.VMM_Name;

            

			String osName = txtHostRecord.VMM_OSName;
			String hypervisor = txtHostRecord.VMM_Name; 
            		
		    hostVO.setVmm(false);
			//getting all Host OS Type from enum
			hostOS[] hostOSTypes = HostType.hostOS.values();
			hostVO.setOsName("");
			for (hostOS hostOSType : hostOSTypes) {
				if (osName.toLowerCase().contains(hostOSType.getValue().toLowerCase())) {
					hostVO.setOsName(TDPConfig.getConfiguration().getString(HelperConstant.IMAGES_ROOT_PATH)+hostOSType.getImageName()); // xxx should be in javascript?
                                        if (hostOSType.getVmmImageNeeded().equals("false"))
                                            skipAddingVMMImage = true;
                                        break;
				}
			}
			
			//getting all Host VMM Type from enum
			hostVMM[] hostVMMTypes = HostType.hostVMM.values();
			hostVO.setHypervisorName("");
			for (hostVMM hostOSType : hostVMMTypes) {
				if((hypervisor.toLowerCase().contains(hostOSType.getValue().toLowerCase())) &&
                                        (skipAddingVMMImage == false)){
					hostVO.setHypervisorName(TDPConfig.getConfiguration().getString(HelperConstant.IMAGES_ROOT_PATH)+hostOSType.getImageName());
                                        break;
				}
			}
			
			//hostVO.setUpdatedOn(formatter.format(hostDetailsEntityVO.getUpdatedOn()));//
//                        if (trustAssertion != null)
//                            hostVO.setUpdatedOn(trustAssertion.getDate().toString());
//                        else
//                            // Bug: 445 - To shown the updated date when the host is in the unknown state
//                            hostVO.setUpdatedOn(new SimpleDateFormat("EEE MMM d HH:MM:ss z yyyy").format(new Date()));
                            
			hostVO.setHostID(txtHostRecord.HostName);        
    }
    
    public static String formateXMLString(String inputXML){
        StreamResult xmlOutput = null;
        try {
        Source xmlInput = new StreamSource(new StringReader(inputXML));
        StringWriter stringWriter = new StringWriter();
        xmlOutput = new StreamResult(stringWriter);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer(); 
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        transformer.transform(xmlInput, xmlOutput);
    } catch (Exception e) {
        throw new RuntimeException(e); // simple exception handling, please review it
    }
        return xmlOutput.getWriter().toString();
    }
    
   public static HostDetailsEntityVO getHostVOObjectFromTxtHostRecord(TxtHostRecord txtHostDetail) {
    	HostDetailsEntityVO entityVO = new HostDetailsEntityVO();
		entityVO.setHostId(getConvertedHostName(txtHostDetail.HostName));
		entityVO.setHostName(txtHostDetail.HostName);
		entityVO.setHostIPAddress(txtHostDetail.IPAddress);
		entityVO.setHostPort(txtHostDetail.Port.toString());
		entityVO.setHostDescription(txtHostDetail.Description);
		entityVO.setBiosName(txtHostDetail.BIOS_Name);
		entityVO.setBiosBuildNo(txtHostDetail.BIOS_Version);
		entityVO.setVmmName(txtHostDetail.VMM_OSName+" "+txtHostDetail.VMM_OSVersion+HelperConstant.OS_VMM_INFORMATION_SEPERATOR+txtHostDetail.VMM_Name);
		entityVO.setVmmBuildNo(txtHostDetail.VMM_Version);
		entityVO.setvCenterDetails(txtHostDetail.AddOn_Connection_String);
		entityVO.setOemName(txtHostDetail.BIOS_Oem);
		entityVO.setLocation(txtHostDetail.Location);
		entityVO.setEmailAddress(txtHostDetail.Email);
    	return entityVO;
    }

	private static String getConvertedHostName(String hostName) {
	String newHostID = hostName.replaceAll(Pattern.quote("."), "_");
	return newHostID.replaceAll(Pattern.quote(" "), "_");
}

	public static List<MleDetailsEntityVO> getMleVOListWhereOEMNotNull(List<MleData> mleDataList) {
		List<MleDetailsEntityVO> detailsEntityVOs = new ArrayList<MleDetailsEntityVO>();
		for (MleData data : mleDataList) {
			if (data.getOemName() != null && !(data.getOemName().length() == 0)) {
				MleDetailsEntityVO entityVO = new MleDetailsEntityVO();
				entityVO.setMleId(null);
				entityVO.setMleName(data.getName());
				entityVO.setMleVersion(data.getVersion());
				entityVO.setAttestationType(data.getAttestationType());
				entityVO.setMleType(data.getMleType());
				//entityVO.setManifestList(data.getManifestList().toString());
				entityVO.setOsName(data.getOsName());
				entityVO.setOsVersion(data.getOsVersion());
				entityVO.setOemName(data.getOemName());
				detailsEntityVOs.add(entityVO);
			}
		}
		return detailsEntityVOs;
	}

	public static List<MleDetailsEntityVO> getMleVOListWhereOEMIsNull(List<MleData> searchMLE) {
		List<MleDetailsEntityVO> detailsEntityVOs = new ArrayList<MleDetailsEntityVO>();
		for (MleData data : searchMLE) {
			if (data.getOemName() == null || data.getOemName().length() == 0) {
				MleDetailsEntityVO entityVO = new MleDetailsEntityVO();
				entityVO.setMleId(null);
				entityVO.setMleName(data.getName());
				entityVO.setMleVersion(data.getVersion());
				entityVO.setAttestationType(data.getAttestationType());
				entityVO.setMleType(data.getMleType());
				//entityVO.setManifestList(data.getManifestList().toString());
				entityVO.setOsName(data.getOsName());
				entityVO.setOsVersion(data.getOsVersion());
				entityVO.setOemName(data.getOemName());
				detailsEntityVOs.add(entityVO);
			}
		}
		return detailsEntityVOs;
	}

	public static List<HostDetailsEntityVO> getHostVOListFromTxtHostRecord(List<TxtHostRecord> txtHostDetails) {
		List<HostDetailsEntityVO> detailsEntityVOs = new ArrayList<HostDetailsEntityVO>();
		for (TxtHostRecord tblHostDetail : txtHostDetails) {
			detailsEntityVOs.add(getHostVOObjectFromTxtHostRecord(tblHostDetail));
		}
    	return detailsEntityVOs;
	}
}
