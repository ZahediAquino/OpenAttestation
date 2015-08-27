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

package com.intel.mtwilson.as.business.trust;

import com.intel.mtwilson.util.net.Hostname;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mountwilson.manifest.IManifestStrategy;
import com.intel.mountwilson.manifest.IManifestStrategyFactory;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mountwilson.manifest.factory.DefaultManifestStrategyFactory;
import com.intel.mtwilson.agent.*;
import com.intel.mtwilson.as.business.AssetTagCertBO;
import com.intel.mtwilson.as.business.HostBO;
import com.intel.mtwilson.as.business.trust.HostTrustBO;
import com.intel.mtwilson.as.business.trust.gkv.IGKVStrategy;
import com.intel.mtwilson.as.business.trust.gkv.factory.DefaultGKVStrategyFactory;
import com.intel.mtwilson.as.controller.MwKeystoreJpaController;
import com.intel.mtwilson.as.controller.TblLocationPcrJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.data.MwAssetTagCertificate;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblLocationPcr;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.as.helper.BaseBO;
import com.intel.mtwilson.crypto.CryptographyException;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.util.crypto.Sha1Digest;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 *
 * @author dsmagadx
 */
public class HostTrustBO extends BaseBO {
    private static final Logger log = LoggerFactory.getLogger(HostTrustBO.class);
    Marker sysLogMarker = MarkerFactory.getMarker("SYSLOG"); // TODO we should create a single class to contain all the markers we want to use throughout the code
    private final int CACHE_VALIDITY_SECS = 3600;
    
    private HostBO hostBO;
    private HashMap<String, String> hostStatus = new HashMap<String, String>();
    
    public HostTrustBO() {
    }
    
    public void setHostBO(HostBO hostBO) { this.hostBO = hostBO; }
              
    /**
     * 
     * @param hostName must not be null
     * @return 
     */
    public HostTrustStatus getTrustStatus(Hostname hostName) {
        HashMap<String, ? extends IManifest> pcrManifestMap;
        HashMap<String, ? extends IManifest> gkvBiosPcrManifestMap, gkvVmmPcrManifestMap;
        if( hostName == null ) { throw new IllegalArgumentException("missing hostname"); }
        TblHosts tblHosts = null;
        try {
            tblHosts = getHostByIpAddress(InetAddress.getByName(hostName.toString()).getHostAddress());
        } catch (UnknownHostException e) {
            throw new ASException(e);
        }
        if (tblHosts == null) {
            throw new ASException(
                    ErrorCode.AS_HOST_NOT_FOUND,
                    hostName.toString());
        }
        log.info( "VMM name for host is {}", tblHosts.getVmmMleId().getName());
        log.info( "OS name for host is {}", tblHosts.getVmmMleId().getOsId().getName());

        // bug #538 first check if the host supports tpm
        HostAgentFactory factory = new HostAgentFactory();
        HostAgent agent = factory.getHostAgent(tblHosts);
        if( !agent.isTpmAvailable() ) {
            //Bug 510 add a blank row in the ta log for this host. this is so the host does not report mle's incorrectly.  
            logBlankTrustStatus(tblHosts);
            throw new ASException(ErrorCode.AS_INTEL_TXT_NOT_ENABLED, hostName.toString());
        }
        
        IManifestStrategy manifestStrategy = getManifestStrategy(tblHosts);

        try {
            long start = System.currentTimeMillis();
            
            pcrManifestMap = manifestStrategy.getManifest(tblHosts);
            log.info("Manifest Time {}", (System.currentTimeMillis() - start));
            
        } catch (ASException e) {
            throw e;
        } catch (Exception e) {
            throw new ASException(e);
        }
        long start = System.currentTimeMillis();
        log.info("PCRS from the VMM host {}", pcrManifestMap);

        /**
         * Get GKV for the given host
		 *
         */
        IGKVStrategy gkvStrategy = getGkvStrategy(tblHosts);

        gkvBiosPcrManifestMap = gkvStrategy.getBiosGoodKnownManifest(tblHosts.getBiosMleId().getName(),
                tblHosts.getBiosMleId().getVersion(), tblHosts.getBiosMleId().getOemId().getName());

        gkvVmmPcrManifestMap = gkvStrategy.getVmmGoodKnownManifest(tblHosts.getVmmMleId().getName(),
                tblHosts.getVmmMleId().getVersion(), tblHosts.getVmmMleId().getOsId().getName(), tblHosts.getVmmMleId().getOsId().getVersion(),
                tblHosts.getId());

        /**
         * Verify trust
		 *
         */
        HostTrustStatus trust = verifyTrust(tblHosts, pcrManifestMap,
                gkvBiosPcrManifestMap, gkvVmmPcrManifestMap);

        log.info( "Verfication Time {}", (System.currentTimeMillis() - start));

        return trust;
    }

    protected TxtHostRecord createTxtHostRecord(TblHosts from) {
        TxtHostRecord to = new TxtHostRecord();
        to.AddOn_Connection_String = from.getAddOnConnectionInfo();
        to.BIOS_Name = from.getBiosMleId().getName();
        to.BIOS_Version = from.getBiosMleId().getVersion();
        to.BIOS_Oem = from.getBiosMleId().getOemId().getName();
        to.Description = from.getDescription();
        to.Email = from.getEmail();
        to.HostName = from.getName();
        to.IPAddress = from.getIPAddress();
        to.Location = from.getLocation();
        to.Port = from.getPort();
        to.VMM_Name = from.getVmmMleId().getName();
        to.VMM_Version = from.getVmmMleId().getVersion();
        to.VMM_OSName = from.getVmmMleId().getOsId().getName();
        to.VMM_OSVersion = from.getVmmMleId().getOsId().getVersion();
        to.AIK_Certificate = from.getAIKCertificate();
        return to;
    }

    /**
     * Gets the host trust status from trust agent
     *
     * @param hostName must not be null
     * @return {@link String}
     */
    public String getTrustStatusString(Hostname hostName) { // datatype.Hostname

        HostTrustStatus trust = getTrustStatus(hostName);

        String response = toString(trust);

        log.info("Overall trust status " + response);

        return response;
    }

    private HostTrustStatus verifyTrust(TblHosts host,
            HashMap<String, ? extends IManifest> pcrManifestMap,
            HashMap<String, ? extends IManifest> gkvBiosPcrManifestMap,
            HashMap<String, ? extends IManifest> gkvVmmPcrManifestMap) {

        HostTrustStatus trust = new HostTrustStatus();

        /*
         * Verify Bios trust
         */
        trust.bios = verifyTrust(host, host.getBiosMleId(), pcrManifestMap,
                gkvBiosPcrManifestMap);
        /*
         * Verify Vmm trust
         */
        trust.vmm = verifyTrust(host, host.getVmmMleId(), pcrManifestMap,
                gkvVmmPcrManifestMap);
        
        /*
         * Verify Location trust 
         */
        trust.location = host.getLocation() != null; // if location is available (it comes from PCR 22), it's trusted
        MwAssetTagCertificate atagCert = verifyAssetTagCert(host);
        if(atagCert != null){
            trust.asset_tag = verifyAssetTagTrust(host, host.getVmmMleId(), pcrManifestMap, atagCert);
            log.debug("Asset Tag Status Answer: {}", trust.asset_tag);
        }
        logOverallTrustStatus(host, toString(trust));

        return trust;
    }

    private String toString(HostTrustStatus trust) {
        return String.format("BIOS:%d,VMM:%d", (trust.bios) ? 1 : 0,
                (trust.vmm) ? 1 : 0);
    }
    
    private MwAssetTagCertificate verifyAssetTagCert(TblHosts tblHosts){
         try {
            log.debug("Checking if there are any asset tag certificates mapped to host with ID : {}", tblHosts.getId());
            // Load the asset tag certificate only if it is associated and valid.
            AssetTagCertBO atagCertBO = new AssetTagCertBO();
            MwAssetTagCertificate atagCertForHost = atagCertBO.findValidAssetTagCertForHost(tblHosts.getId());            
            if (atagCertForHost != null) {
                log.debug("Asset tag certificate is associated to host {} with status {}.", tblHosts.getName(), atagCertForHost.getRevoked());
                return atagCertForHost;
            }
            else {
                log.debug("Asset tag certificate is either not associated or valid for host {}.", tblHosts.getName());
            }
        } catch (Exception ex) {
            log.error("Exception when looking up the asset tag whitelist.", ex);
            // We cannot do anything ... just log the error and proceed
            log.info("Error during look up of asset tag certificates for the host {}", tblHosts.getName());
            return null;
        }
         return null;
    }
    
    private boolean verifyAssetTagTrust(TblHosts host,
            TblMle mle,
            HashMap<String, ? extends IManifest> pcrManifestMap,
            MwAssetTagCertificate atagCert) {
        boolean response = true;

        String certSha1 = Sha1Digest.valueOf(atagCert.getPCREvent()).toString();
//        if (gkvPcrManifestMap.size() <= 0) {
//            throw new ASException(ErrorCode.AS_MISSING_MANIFEST, mle.getName(),
//                    mle.getVersion());
//        }
        log.debug("Cert Sha1: " + certSha1);
        PcrManifest goodKnownValue = (PcrManifest) pcrManifestMap.get("22");
        //log.debug("Checking PCR 22: {} - {}",certSha1, goodKnownValue.getPcrValue());
        String pcr = "22";
        //log.debug("PCR to be checked: {} - {}",pcr, pcrManifestMap.get(pcr));
        if(goodKnownValue != null)
        {
            boolean trustStatus = certSha1.toUpperCase().equals(goodKnownValue.getPcrValue().toUpperCase());
            log.info(String.format("PCR %s Host Trust status %s", pcr,String.valueOf(trustStatus)));
            if (!trustStatus) {
                response = false;
            }
    //            if (pcrManifestMap.containsKey(pcr)) {
    //                IManifest pcrMf = pcrManifestMap.get(pcr);
    //                boolean trustStatus = pcrMf.verify(gkvPcrManifestMap.get(pcr));
    //                log.info(String.format("PCR %s Host Trust status %s", pcr,
    //                        String.valueOf(trustStatus)));
    //                /*
    //                 * Log to database
    //                 */
    //                logTrustStatus(host, mle,  pcrMf);
    //
    //                if (!trustStatus) {
    //                    response = false;
    //                }
    //
    //            } else {
    //                log.info(String.format("PCR %s not found in manifest.", pcr));
    //                throw new ASException(ErrorCode.AS_PCR_NOT_FOUND,pcr);
    //            }
            return true;
        } else {
            return false;
        }
    }

    private boolean verifyTrust(TblHosts host, TblMle mle,
            HashMap<String, ? extends IManifest> pcrManifestMap,
            HashMap<String, ? extends IManifest> gkvPcrManifestMap) {
        boolean response = true;

        if (gkvPcrManifestMap.size() <= 0) {
            throw new ASException(ErrorCode.AS_MISSING_MANIFEST, mle.getName(),
                    mle.getVersion());
        }

        for (String pcr : gkvPcrManifestMap.keySet()) {
            log.debug("PCR to be checked: {}",pcr);
            if (pcrManifestMap.containsKey(pcr)) {
                IManifest pcrMf = pcrManifestMap.get(pcr);
                boolean trustStatus = pcrMf.verify(gkvPcrManifestMap.get(pcr));
                log.info(String.format("PCR %s Host Trust status %s", pcr,
                        String.valueOf(trustStatus)));
                /*
                 * Log to database
                 */
                logTrustStatus(host, mle,  pcrMf);

                if (!trustStatus) {
                    response = false;
                }

            } else {
                log.info(String.format("PCR %s not found in manifest.", pcr));
                throw new ASException(ErrorCode.AS_PCR_NOT_FOUND,pcr);
            }
        }

        return response;
    }

    private void logTrustStatus(TblHosts host, TblMle mle, IManifest manifest) {
        Date today = new Date(System.currentTimeMillis());


        PcrManifest pcrManifest = (PcrManifest)manifest;
        
        TblTaLog taLog = new TblTaLog();
        taLog.setHostID(host.getId());
        taLog.setMleId(mle.getId());
        taLog.setManifestName(String.valueOf(pcrManifest.getPcrNumber()));
        taLog.setManifestValue(pcrManifest.getPcrValue());
        taLog.setTrustStatus(pcrManifest.getVerifyStatus());
        taLog.setUpdatedOn(today);

        getTblTaLogJpaController().create(taLog);
        

    }

    private void logOverallTrustStatus(TblHosts host, String response) {
        Date today = new Date(System.currentTimeMillis());

        TblTaLog taLog = new TblTaLog();
        taLog.setHostID(host.getId());
        taLog.setMleId(0);
        taLog.setTrustStatus(false);
        taLog.setError(response);
        taLog.setManifestName(" ");
        taLog.setManifestValue(" ");
        taLog.setUpdatedOn(today);

        getTblTaLogJpaController().create(taLog);

    }

    /*Bug 510
     * Added to support removal of TPM from host which was previously enabled. 
     * Adding blank row to ta log table will prevent an invalid trust report
     */
    private void logBlankTrustStatus(TblHosts host) {
        Date today = new Date(System.currentTimeMillis());

        TblTaLog taLog = new TblTaLog();
        taLog.setHostID(host.getId());
        taLog.setMleId(0);
        taLog.setTrustStatus(false);
        taLog.setManifestName("");
        taLog.setManifestValue("");
        taLog.setUpdatedOn(today);

        new TblTaLogJpaController(getEntityManagerFactory()).create(taLog);

    }
    
    private TblHosts getHostByName(Hostname hostName) { // datatype.Hostname
        try {
            return hostBO.getHostByName(hostName);
        }
        catch(CryptographyException e) {
            throw new ASException(e,ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
        }
    }
  
    public TblHosts getHostByIpAddress(String ipAddress) {
        try {
            return hostBO.getHostByIpAddress(ipAddress);
        }
        catch(CryptographyException e) {
            throw new ASException(e,ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
        }
    }

    public OpenStackHostTrustLevelReport getPollHosts(OpenStackHostTrustLevelQuery input) {
        OpenStackHostTrustLevelReport hostTrusts = new OpenStackHostTrustLevelReport();
        Date today = new Date(System.currentTimeMillis());
        String trustLevel;

        // fetch pcr value from host agent in parallel
        for (final Hostname hostName : input.hosts) {
            hostStatus.put(hostName.getHostname(), "");
            Thread thread = new Thread() {
                public void run() {
                    try {
                        String hostTrustStatus = getTrustStatusString(hostName);
                        log.info("The trust status of {} is :{}",
                                new String[] { hostName.toString(), hostTrustStatus });

                        hostStatus.put(hostName.getHostname(), hostTrustStatus);
                    } catch (ASException e) {
                        log.error("Error while getting status of host " + hostName, e);
                        hostStatus.put(hostName.getHostname(), "unknown");
                    } catch (Exception e) {
                        log.error("Error while getting status of host " + hostName, e);
                        hostStatus.put(hostName.getHostname(), "unknown");
                    }
                }
            };
            thread.start();
        }

        while (!isAllAttested(input)) {
            try {
                Thread.sleep(ASConfig.getTrustAgentSleepTimeinMilliSecs());
            } catch (InterruptedException e) {
                log.error("Error while sleeping " + e);
            }
        }

        for (Hostname hostName : input.hosts) {
            try {
                String hostTrustStatus = hostStatus.get(hostName.getHostname());
                log.info("The trust status of {} is :{}",
                        new String[] { hostName.toString(), hostTrustStatus });
                if(hostTrustStatus != null){
                    if (hostTrustStatus.equals("unknown")) {
                        trustLevel = "unknown";
                    } else {
                        trustLevel = parseTrustStatus(hostTrustStatus);
                    }
                } else
                    throw new NullPointerException();
            } catch (ASException e) {
                log.error("Error while getting trust of host " + hostName, e);
                trustLevel = "unknown";
            } catch (Exception e) {
                log.error("Error while getting trust of host " + hostName, e);
                trustLevel = "unknown";
            }
            HostTrustLevel1String trust = new HostTrustLevel1String();
            trust.hostname = hostName.toString();
            trust.trustLevel = trustLevel;
            trust.vtime = today;
            // trust.timestamp = Util.getDateString(today);
            // hostTrusts.pollHosts.put(hostName, trust);
            hostTrusts.pollHosts.add(trust);
        }
        return hostTrusts;
    }

    /**
     * decide whether all hosts has attested;
     * @return true if all has attested, else false
     */
    public boolean isAllAttested(OpenStackHostTrustLevelQuery input){
        for (Hostname hostName : input.hosts) {
            if (hostStatus.get(hostName.getHostname()).equalsIgnoreCase("")){
                return false;
            }
        }
        return true;
    }

    private String parseTrustStatus(String hostTrustStatus) {
        String result = "untrusted";

        Boolean biostrust = false;
        Boolean vmmtrust = false;
        String[] parts = hostTrustStatus.split(",");

        for (String part : parts) {
            String[] subParts = part.split(":");
            if (subParts[0].equals("BIOS")) {
                biostrust = subParts[1].equals("1");
            } else {
                vmmtrust = subParts[1].equals("1");
            }

        }

        if (biostrust && vmmtrust) {
            result = "trusted";
        }

        return result;
    }

    // PREMIUM FEATURE ? 
    /**
     * Gets the location of the host from db table tblHosts
     *
     * @param hostName
     * @return {@link HostLocation}
     */
    public HostLocation getHostLocation(Hostname hostName) {
        try {
            TblHosts tblHosts = getHostByName(hostName);

            if (tblHosts == null) {
                throw new ASException(
                        ErrorCode.AS_HOST_NOT_FOUND,
                        String.format(
                        "%s",
                        hostName));
            }

            HostLocation location = new HostLocation(tblHosts.getLocation());
            return location;
        } catch (ASException e) {
            throw e;
        } catch (Exception e) {
            throw new ASException(e);
        }
    }
    
    /**
     * Author: Sudhir
     * 
     * Add a new location mapping entry into the table.
     * 
     * @param hlObj
     * @return 
     */
    public Boolean addHostLocation(HostLocation hlObj) {

        TblLocationPcrJpaController locJpaController = new TblLocationPcrJpaController(getEntityManagerFactory());
        try {
            if (hlObj != null && !hlObj.white_list_value.isEmpty()) {
                TblLocationPcr locPCR = locJpaController.findTblLocationPcrByPcrValueEx(hlObj.white_list_value);
                if (locPCR != null) {
                    log.info(String.format("An entry already existing in the location table for the white list specified [%s | %s]"
                            , locPCR.getLocation(), hlObj.white_list_value));
                    if (locPCR.getLocation().equals(hlObj.location)) {
                        // No need to do anything. Just exit.
                        return true;
                    }
                    else {
                        // Need to update the entry
                        log.info(String.format("Updating the location value for the white list specified to %s.", hlObj.location));
                        locPCR.setLocation(hlObj.location);
                        locJpaController.edit(locPCR);
                    }
                } else {
                    // Add a new entry for the location mapping table.
                    locPCR = new TblLocationPcr();
                    locPCR.setLocation(hlObj.location);
                    locPCR.setPcrValue(hlObj.white_list_value);
                    locJpaController.create(locPCR);
                    log.info(String.format("Successfully added a new location value %s with white list %s.", hlObj.location, hlObj.white_list_value));
                }
            }
        } catch (ASException e) {
            throw e;
        } catch (Exception e) {
            throw new ASException( e);
        }

        return true;
    }
    



    public HostTrust getTrustWithCache(String host, Boolean forceVerify) {
        log.info("Getting trust for host: " + host + " Force verify flag: " + forceVerify);
        try {
            
            if(forceVerify != true){
                TblHosts tblHosts = getHostByName(new Hostname(host));
                if(tblHosts != null){
                    TblTaLog tblTaLog = new TblTaLogJpaController(getEntityManagerFactory()).getHostTALogEntryBefore(
                            tblHosts.getId() , getCacheStaleAfter() );
                    
                    if(tblTaLog != null)
                        return getHostTrustObj(tblTaLog);
                }else{
                    throw new ASException(
                            ErrorCode.AS_HOST_NOT_FOUND,
                                       host);
                }
            }
        
           log.info("Getting trust status from host.");
        
           HostTrustStatus status = getTrustStatus(new Hostname(host));
           
           HostTrust hostTrust = new HostTrust(ErrorCode.OK,"OK");
           hostTrust.setBiosStatus((status.bios)?1:0);
           hostTrust.setVmmStatus((status.vmm)?1:0);
           hostTrust.setIpAddress(host);
           
           return hostTrust;
            
        } catch (ASException e) {
            log.error("Error while getting trust for host " + host,e );
            return new HostTrust(e.getErrorCode(),e.getErrorMessage(),host,null,null);
        }catch(Exception e){
            log.error("Error while getting trust for host " + host,e );
            return new HostTrust(ErrorCode.SYSTEM_ERROR,
                    new AuthResponse(ErrorCode.SYSTEM_ERROR,e.getMessage()).getErrorMessage(),host,null,null);
        }

    }
    
    
    private Date getCacheStaleAfter(){
        return new DateTime().minusSeconds(CACHE_VALIDITY_SECS).toDate();
    }
    
    
    private HostTrust getHostTrustObj(TblTaLog tblTaLog) {
        HostTrust hostTrust = new HostTrust(ErrorCode.OK,"");
        
        String[] parts = tblTaLog.getError().split(",");
        
        for(String part : parts){
            String[] subparts = part.split(":");
            if(subparts[0].equalsIgnoreCase("BIOS")){
                hostTrust.setBiosStatus(Integer.valueOf(subparts[1]));
            }else{
                hostTrust.setVmmStatus(Integer.valueOf(subparts[1]));
            }
        }     
        
        return hostTrust;
    }

    public IManifestStrategy getManifestStrategy(TblHosts tblHosts) {
    	IManifestStrategyFactory strategyFactory = getManifestStrategyFactory();
    	return strategyFactory.getManifestStategy(tblHosts, getEntityManagerFactory());
    }
    
    public IManifestStrategyFactory getManifestStrategyFactory() {
    	return new DefaultManifestStrategyFactory();
    }
    
    public IGKVStrategy getGkvStrategy(TblHosts tblHosts) {
    	return new DefaultGKVStrategyFactory().getGkStrategy(tblHosts);
    }
    
    public TblTaLogJpaController getTblTaLogJpaController() {
    	return new TblTaLogJpaController(getEntityManagerFactory());
    }

}

