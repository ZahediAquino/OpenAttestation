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

package com.intel.mtwilson.as.business;

import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.as.data.TblPcrManifest;
import com.intel.mtwilson.as.business.trust.Util;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.helper.BaseBO;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.util.net.Hostname;
import com.intel.mtwilson.as.controller.TblHostsJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mountwilson.as.hostmanifestreport.data.HostManifestReportType;
import com.intel.mountwilson.as.hostmanifestreport.data.ManifestType;
import com.intel.mountwilson.as.hosttrustreport.data.HostType;
import com.intel.mountwilson.as.hosttrustreport.data.HostsTrustReportType;
import com.intel.mountwilson.manifest.IManifestStrategy;
import com.intel.mountwilson.manifest.IManifestStrategyFactory;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mountwilson.manifest.factory.DefaultManifestStrategyFactory;
import com.intel.mtwilson.as.controller.TblHostSpecificManifestJpaController;
import com.intel.mtwilson.as.data.MwAssetTagCertificate;
import com.intel.mtwilson.as.data.TblModuleManifest;
import com.intel.mtwilson.as.data.TblModuleManifestLog;
import com.intel.mtwilson.crypto.CryptographyException;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.util.crypto.Sha1Digest;
import java.io.IOException;
import java.io.StringWriter;
import java.util.*;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
//import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dsmagadx
 */
public class ReportsBO extends BaseBO {
    Logger logger = LoggerFactory.getLogger(getClass().getName());
    private static String ASSET_TAG_PCR = "22";
    
    public HostsTrustReportType getTrustReport(Collection<Hostname> hostNames) { // datatype.Hostname
        try {
            HostsTrustReportType hostsTrustReportType = new HostsTrustReportType();
            for (Hostname host : hostNames) {
                TblHosts tblHosts = getTblHostsJpaController().findByName(host.toString()); // datatype.Hostname


                if (tblHosts == null) {
                    throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, host);
                }

                List<TblTaLog> logs = getTblTaLogJpaController().findTrustStatusByHostId(tblHosts.getId(), 5);

                if (logs != null) {

                    for (TblTaLog log : logs) {
                        HostType hostType = new HostType();
                        hostType.setHostName(host.toString()); // datatype.Hostname
                        hostType.setMLEInfo(getMleInfo(tblHosts));
                        hostType.setTrustStatus(getTrustStatus(log.getError()));
                        hostType.setVerifiedOn(Util.getCalendar(log.getUpdatedOn()));
                        hostsTrustReportType.getHost().add(hostType);
                    }
                }


            }
            return hostsTrustReportType;
        } catch (CryptographyException e) {
            throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
        } catch (Exception e) {
            throw new ASException(e);
        }

    }

    public HostManifestReportType getReportManifest(Hostname hostName) {  // datatype.Hostname
        HostManifestReportType hostManifestReportType = new HostManifestReportType();

        /*
         * if (hostName == null || hostName.isEmpty()) { throw new
         * ASException(ErrorCode.VALIDATION_ERROR, "Input Hostname " + hostName
         * + " is empty."); }
         *
         */
        TblHosts tblHosts = null;
        try {
            tblHosts = getTblHostsJpaController().findByName(hostName.toString()); // datatype.Hostname
        } catch (CryptographyException e) {
            throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
        }

        if (tblHosts == null) {
            throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, hostName.toString());
        }

        Date lastStatusTs = getTblTaLogJpaController().findLastStatusTs(tblHosts.getId());


        if (lastStatusTs != null) {
            List<TblTaLog> logs = getTblTaLogJpaController().findLogsByHostId(tblHosts.getId(), lastStatusTs);
            com.intel.mountwilson.as.hostmanifestreport.data.HostType hostType = new com.intel.mountwilson.as.hostmanifestreport.data.HostType();
            hostType.setName(hostName.toString()); // datatype.Hostname
            if (logs != null) {
                for (TblTaLog log : logs) {
                    ManifestType manifest = new ManifestType();
                    manifest.setName(Integer.parseInt(log.getManifestName()));
                    manifest.setValue(log.getManifestValue());
                    manifest.setVerifiedOn(Util.getCalendar(log.getUpdatedOn()));
                    manifest.setTrustStatus(getTrustStatus(log.getTrustStatus()));
                    hostType.getManifest().add(manifest);
                }
            }

            hostManifestReportType.setHost(hostType);
        }
        return hostManifestReportType;
    }

    private String getMleInfo(TblHosts tblHosts) {
        return String.format("BIOS:%s-%s,VMM:%s:%s",
                tblHosts.getBiosMleId().getName(),
                tblHosts.getBiosMleId().getVersion(),
                tblHosts.getVmmMleId().getName(),
                tblHosts.getVmmMleId().getVersion());
    }

    private Integer getTrustStatus(String trustString) {
        int bios = 0;
        int vmm = 0;
        String[] parts = trustString.split(",");
        for (String sub : parts) {
            String[] subParts = sub.split(":");
            if (subParts[0].equals("BIOS")) {
                bios = Integer.parseInt(subParts[1]);
            } else if(subParts[0].equals("VMM")) {
                vmm = Integer.parseInt(subParts[1]);
            }
        }
        return (bios == 1 && vmm == 1) ? 1 : 0;

    }

    private Integer getTrustStatus(boolean trustStatus) {
        if (trustStatus) {
            return 1;
        } else {
            return 0;
        }
    }

    // BUG #497 XXX TODO needs rewrite to use HostAgentFactory and HostAgent interfaces
    public String getHostAttestationReport(Hostname hostName) {
        XMLOutputFactory xof = XMLOutputFactory.newInstance();
        XMLStreamWriter xtw;
        StringWriter sw = new StringWriter();
        IManifestStrategy manifestStrategy;
        IManifestStrategyFactory strategyFactory;
        HashMap<String, ? extends IManifest> pcrManifestMap = null;
        TblHosts tblHosts = null;
        String attestationReport = "";

        try {

            tblHosts = getTblHostsJpaController().findByName(hostName.toString());

            if (tblHosts == null) {
                throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, hostName.toString());
            }

            manifestStrategy = getManifestStrategy(tblHosts);
           // BUG #497  this is now obtained by IntelHostAgent using TAHelper's getQuoteInformationForHost which is what was called by TrustAgentManifestStrategy.getManifest()
            pcrManifestMap = manifestStrategy.getManifest(tblHosts); 

        } catch (ASException aex) {

            throw aex;


        } catch (CryptographyException e) {
            throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
        } catch (Exception ex) {

            throw new ASException(ex);
        }

        try {
            // XXX BUG #497 this entire section in try{}catch{} has  moved to TAHelper and used by IntelHostAgent
            
            // We need to check if the host supports TPM or not. Only way we can do it
            // using the host table contents is by looking at the AIK Certificate. Based
            // on this flag we generate the attestation report.
            boolean tpmSupport = true;
            String hostType = tblHosts.getVmmMleId().getName();

            if (tblHosts.getAIKCertificate() == null || tblHosts.getAIKCertificate().isEmpty()) {
                tpmSupport = false;
            }

            // xtw = xof.createXMLStreamWriter(new FileWriter("c:\\temp\\nb_xml.xml"));
            xtw = xof.createXMLStreamWriter(sw);
            xtw.writeStartDocument();
            xtw.writeStartElement("Host_Attestation_Report");
            xtw.writeAttribute("Host_Name", hostName.toString());
            xtw.writeAttribute("Host_VMM", hostType);
            xtw.writeAttribute("TXT_Support", String.valueOf(tpmSupport));

            if (tpmSupport == true) {
                ArrayList<IManifest> pcrMFList = new ArrayList<IManifest>();
                pcrMFList.addAll(pcrManifestMap.values());

                for (IManifest pcrInfo : pcrMFList) {
                    PcrManifest pInfo = (PcrManifest) pcrInfo;
                    xtw.writeStartElement("PCRInfo");
                    xtw.writeAttribute("ComponentName", String.valueOf(pInfo.getPcrNumber()));
                    xtw.writeAttribute("DigestValue", pInfo.getPcrValue().toUpperCase());
                    xtw.writeEndElement();
                }
            } else {
                xtw.writeStartElement("PCRInfo");
                xtw.writeAttribute("Error", "Host does not support TPM.");
                xtw.writeEndElement();
            }

            xtw.writeEndElement();
            xtw.writeEndDocument();
            xtw.flush();
            xtw.close();
            attestationReport = sw.toString();

        } catch (Exception ex) {

            throw new ASException(ex);
        }

        return attestationReport;
    }

    public AttestationReport getAttestationReport(Hostname hostName, Boolean failureOnly) throws NumberFormatException, IOException {

        AttestationReport attestationReport = new AttestationReport();

        TblHosts tblHosts = null;
		try {
			tblHosts = getTblHostsJpaController().findByName(hostName.toString()); // datatype.Hostname
		} catch (CryptographyException e) {
			throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR,
					e.getCause() == null ? e.getMessage() : e.getCause()
							.getMessage());
		}

        if (tblHosts == null) {
            throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, hostName.toString());
        }

        Date lastStatusTs = getTblTaLogJpaController().findLastStatusTs(tblHosts.getId());


        if (lastStatusTs != null) {
            List<TblTaLog> logs = getTblTaLogJpaController().findLogsByHostId(tblHosts.getId(), lastStatusTs);
			com.intel.mountwilson.as.hostmanifestreport.data.HostType hostType = new com.intel.mountwilson.as.hostmanifestreport.data.HostType();
            hostType.setName(hostName.toString()); // datatype.Hostname
            if (logs != null) {
                for (TblTaLog log : logs) {
                    boolean value = (failureOnly && log.getTrustStatus() == false);
                    if (!failureOnly || value) {
                        if (log.getManifestName().equalsIgnoreCase(ASSET_TAG_PCR)) {
                           attestationReport.getPcrLogs().add(getPcrLogReportForAssetTag(log, tblHosts.getId()));
                        }
                        else {
                           attestationReport.getPcrLogs().add(getPcrManifestLog(tblHosts, log, failureOnly));
                        }
                        
                    }
                }
            }
        }

        return attestationReport;
    }
    
    public PcrLogReport getPcrManifestLog(TblHosts tblHosts, TblTaLog log, Boolean failureOnly) throws NumberFormatException, IOException {
        TblPcrManifest tblPcrManifest = getPcrModuleManifest(tblHosts,log.getMleId(),log.getManifestName());
        PcrLogReport manifest = new PcrLogReport();
        manifest.setName(Integer.parseInt(log.getManifestName()));
        manifest.setValue(log.getManifestValue());
        manifest.setVerifiedOn(log.getUpdatedOn());
        manifest.setTrustStatus(getTrustStatus(log.getTrustStatus()));
        manifest.setWhiteListValue(tblPcrManifest.getValue());
        addManifestLogs(tblHosts.getId(), manifest, log, failureOnly,tblPcrManifest);
        return manifest;
    }
    
     private void addManifestLogs(Integer hostId, PcrLogReport manifest, TblTaLog log, Boolean failureOnly,TblPcrManifest tblPcrManifest) throws IOException {
        HashMap<String,ModuleLogReport> moduleReports = new HashMap<>();
        
        if(log.getTblModuleManifestLogCollection() != null){
            logger.debug("addManifestLogs - This is module based attestation with {} of modules.", log.getTblModuleManifestLogCollection().size());
            for (TblModuleManifestLog moduleManifestLog : log.getTblModuleManifestLogCollection()) {
                moduleReports.put(moduleManifestLog.getName(), new ModuleLogReport(moduleManifestLog.getName(),
                        moduleManifestLog.getValue(), moduleManifestLog.getWhitelistValue(),0));
            }
        }
        
        if(!failureOnly){
            logger.debug("FailureOnly flag is false. Adding all manifests.");
            for(TblModuleManifest moduleManifest : tblPcrManifest.getMleId().getTblModuleManifestCollection()){
                if(moduleManifest.getExtendedToPCR().equalsIgnoreCase(tblPcrManifest.getName()) && 
                        !moduleReports.containsKey(moduleManifest.getComponentName())){
                    
                    if( moduleManifest.getUseHostSpecificDigestValue() != null && moduleManifest.getUseHostSpecificDigestValue().booleanValue() ) {
                        // For open source we used to have multiple module manifests for the same hosts. So, the below query by hostID was returning multiple results.
                        //String hostSpecificDigestValue = new TblHostSpecificManifestJpaController(getEntityManagerFactory()).findByHostID(hostId).getDigestValue();
                        
                        //String hostSpecificDigestValue = My.jpa().mwHostSpecificManifest().findByModuleAndHostID(hostId, moduleManifest.getId()).getDigestValue();
                        TblHostSpecificManifestJpaController tblHostSpecificManifestJpaController = getTblHostSpecificManifestJpaController();
                        String hostSpecificDigestValue = tblHostSpecificManifestJpaController.findByModuleAndHostID(hostId, moduleManifest.getId()).getDigestValue();
                                
                        moduleReports.put(moduleManifest.getComponentName(), new ModuleLogReport(moduleManifest.getComponentName(),
                                hostSpecificDigestValue, hostSpecificDigestValue, 1));
                    }
                    else {
                        moduleReports.put(moduleManifest.getComponentName(), new ModuleLogReport(moduleManifest.getComponentName(),
                                moduleManifest.getDigestValue(), moduleManifest.getDigestValue(),1)); 
                    }
                }
            }
        }
        
        manifest.getModuleLogs().addAll(moduleReports.values());

    }

    private TblPcrManifest getPcrModuleManifest(TblHosts tblHosts, Integer mleId, String manifestName) {
        Collection<TblPcrManifest> pcrManifestCollection = null;
        
        if (tblHosts.getVmmMleId().getId().intValue() == mleId.intValue()) {
            pcrManifestCollection = tblHosts.getVmmMleId().getTblPcrManifestCollection();
        } else {
            pcrManifestCollection = tblHosts.getBiosMleId().getTblPcrManifestCollection();
        }

        if (pcrManifestCollection != null) {
            for (TblPcrManifest pcrManifest : pcrManifestCollection) {
                if (pcrManifest.getName().equals(manifestName)) {
                    return pcrManifest;
                }
            }
        }
        throw new ASException(ErrorCode.AS_PCR_MANIFEST_MISSING,manifestName,mleId,tblHosts.getName());
        
    }
    
    public TblHostsJpaController getTblHostsJpaController() throws CryptographyException {
    	return new TblHostsJpaController(getEntityManagerFactory());
    }
    
    public TblTaLogJpaController getTblTaLogJpaController() {
    	return new TblTaLogJpaController(getEntityManagerFactory());
    }
    
    public IManifestStrategy getManifestStrategy(TblHosts tblHosts) {
    	IManifestStrategyFactory strategyFactory = getManifestStrategyFactory();
    	return strategyFactory.getManifestStategy(tblHosts, getEntityManagerFactory());
    }
    
    public IManifestStrategyFactory getManifestStrategyFactory() {
    	return new DefaultManifestStrategyFactory();
    }
    
    public TblHostSpecificManifestJpaController getTblHostSpecificManifestJpaController() {
	return new TblHostSpecificManifestJpaController(getEntityManagerFactory());
    }
    
    private PcrLogReport getPcrLogReportForAssetTag(TblTaLog taLog, Integer hostId) {
        logger.debug("getPcrLogReportForAssetTag : Creating pcr log report for asset tag verification for host with uuid {}.", hostId);
        AssetTagCertBO atagCertBO = new AssetTagCertBO();
        MwAssetTagCertificate atagCert = atagCertBO.findValidAssetTagCertForHost(hostId);
        if (atagCert != null) {  
            logger.debug("getPcrLogReportForAssetTag : Found a valid asset tag certificate for the host with white list value {}", atagCert.getPCREvent().toString());
            PcrLogReport manifest = new PcrLogReport();
            manifest.setName(Integer.parseInt(ASSET_TAG_PCR));
            manifest.setValue(taLog.getManifestValue());
            manifest.setWhiteListValue(new  Sha1Digest(atagCert.getPCREvent()).toString());
            if(manifest.getValue().equalsIgnoreCase(manifest.getWhiteListValue())) {
                manifest.setTrustStatus(1);
            }else{
                manifest.setTrustStatus(0);
            }
            manifest.setVerifiedOn(new Date());
            return manifest;
        }
        return null;
    }
    
    
}
