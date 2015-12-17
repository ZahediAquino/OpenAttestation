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
import com.intel.mtwilson.as.business.trust.gkv.IGKVStrategy;
import com.intel.mtwilson.as.business.trust.gkv.factory.DefaultGKVStrategyFactory;
import com.intel.mtwilson.as.controller.MwKeystoreJpaController;
import com.intel.mtwilson.as.controller.TblLocationPcrJpaController;
import com.intel.mtwilson.as.controller.TblSamlAssertionJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.data.MwAssetTagCertificate;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblLocationPcr;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblSamlAssertion;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.as.helper.BaseBO;
import com.intel.mtwilson.as.rest.HostAttestation;
import com.intel.mtwilson.crypto.CryptographyException;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.saml.SamlAssertion;
import com.intel.mtwilson.saml.SamlGenerator;
import com.intel.mtwilson.saml.TxtHostWithAssetTag;
import com.intel.mtwilson.util.crypto.Sha1Digest;
import com.intel.mtwilson.util.io.FileResource;
import com.intel.mtwilson.util.io.Resource;
import com.intel.mtwilson.util.io.UUID;
import java.io.IOException;
import java.util.Collection;
import java.util.ArrayList;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response.Status;
import org.apache.commons.configuration.ConfigurationException;

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
    
    private Resource samlKeystoreResource = null;
    private HostBO hostBO;
    private HashMap<String, String> hostStatus = new HashMap<String, String>();
    
    public HostTrustBO() {
        loadSamlSigningKey();
    }
    
    public void setHostBO(HostBO hostBO) { this.hostBO = hostBO; }
              
    private void loadSamlSigningKey() {
        /*
        MwKeystore mwKeystore = keystoreJpa.findMwKeystoreByName(SAML_KEYSTORE_NAME);
        if( mwKeystore != null && mwKeystore.getKeystore() != null ) {
            samlKeystoreResource = new ByteArrayResource(mwKeystore.getKeystore());
        }
        */
        //samlKeystoreResource = new FileResource(ResourceFinder.getFile(ASConfig.getConfiguration().getString("saml.keystore.file", "SAML.jks"))); 
        
        
        samlKeystoreResource = new FileResource(ASConfig.getSamlKeystoreFile());
        if(samlKeystoreResource != null)
            log.info("samlKeystoreResource is not null");
        else
            log.info("samlKeystoreResource is null");
    }
    
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
        log.info("tblHosts.getId()" + tblHosts.getId());
        log.info("tblHosts.getIPAddress()" + tblHosts.getIPAddress());
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
        trust.asset_tag = false;
        MwAssetTagCertificate atagCert = verifyAssetTagCert(host);
        if(atagCert != null){
            trust.asset_tag = verifyAssetTagTrust(host, host.getVmmMleId(), pcrManifestMap, atagCert);
        }
        logOverallTrustStatus(host, toString(trust));
         
        return trust;
    }

    private String toString(HostTrustStatus trust) {
        return String.format("BIOS:%d,VMM:%d,ATag:%d", (trust.bios) ? 1 : 0,
                (trust.vmm) ? 1 : 0, (trust.asset_tag) ? 1 : 0);
    }
    
    private MwAssetTagCertificate verifyAssetTagCert(TblHosts tblHosts){
         try {
            log.debug("Checking if there are any asset tag certificates mapped to host with ID : {}", tblHosts.getId());
            // Load the asset tag certificate only if it is associated and valid.
            AssetTagCertBO atagCertBO = new AssetTagCertBO();
            MwAssetTagCertificate atagCertForHost = atagCertBO.findValidAssetTagCertForHost(tblHosts.getId());  
            log.info("atagCertBO.findValidAssetTagCertForHost("+ tblHosts.getId() + ")");
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
        
        String certSha1 = Sha1Digest.valueOf(atagCert.getPCREvent()).toString();

        IManifest pcrMf = pcrManifestMap.get("22");
        PcrManifest goodKnownValue = (PcrManifest) pcrManifestMap.get("22");
        boolean trustStatus;
        if(goodKnownValue != null){
            log.debug("Checking PCR 22: {} - {}",certSha1, goodKnownValue.getPcrValue());
            trustStatus = certSha1.toUpperCase().equalsIgnoreCase(goodKnownValue.getPcrValue().toUpperCase());
        }
        else{
            log.debug("goodKnownValue is null");
            trustStatus = false;
        }
        String pcr = "22";
        
        log.info(String.format("PCR %s Host Trust status %s", pcr, String.valueOf(trustStatus)));
        if(pcrMf != null)
            logTrustStatus(host, mle, pcrMf);
        else {
            log.info("PCR Manifest is null, unable to log Trust Status");
        }
            return trustStatus;
        
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
                if (hostTrustStatus == "unknown") {
                    trustLevel = "unknown";
                } else {
                    log.debug("Processing hostTrustStatus String: {}",hostTrustStatus);
                    trustLevel = parseTrustStatus(hostTrustStatus);
                    log.debug("Trust level obtained: {}",hostTrustStatus);
                }
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
//        Boolean atagtrust = false;
        String[] parts;
        if(hostTrustStatus != null)
            parts = hostTrustStatus.split(",");
        else
            parts = new String[1];
        //Sample Input: BIOS:1,VMM:1,ATag:0
        for (String part : parts) {
            String[] subParts = part.split(":");
            if (subParts[0].equals("BIOS")) {
                biostrust = subParts[1].equals("1");
            } else if(subParts[0].equals("VMM")) {
                vmmtrust = subParts[1].equals("1");
            }
//            else {
//                atagtrust = subParts[1].equals("1");
//            }

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
    
    public String getTrustWithSaml(String host, boolean forceVerify) throws IOException {
        //My.initDataEncryptionKey();
        TblHosts tblHosts = getHostByName(new Hostname((host)));
        return getTrustWithSaml(tblHosts, tblHosts.getName(), forceVerify);
    }
    
    public String getTrustWithSaml(TblHosts tblHosts, String hostId, boolean forceVerify) throws IOException {
        String hostAttestationUuid = new UUID().toString();
        log.debug("Generating new UUID for saml assertion record 1: {}", hostAttestationUuid);
        return getTrustWithSaml(tblHosts, hostId, hostAttestationUuid, forceVerify); //.getSaml();
    }
    
    public String getTrustWithSaml(TblHosts tblHosts, String hostId, String hostAttestationUuid, boolean forceVerify) throws IOException {
        log.debug("getTrustWithSaml: Getting trust for host: " + tblHosts.getName() + " Force verify flag: " + forceVerify);
        // Bug: 702: For host not supporting TXT, we need to return back a proper error
        // make sure the DEK is set for this thread
        
//        My.initDataEncryptionKey();
//        TblHosts tblHosts = getHostByName(new Hostname((host)));
        HostAgentFactory factory = new HostAgentFactory();
        HostAgent agent = factory.getHostAgent(tblHosts);
       // log.info("Value of the TPM flag is : " +  Boolean.toString(agent.isTpmEnabled()));
        
        if (!agent.isTpmAvailable()) {
            throw new ASException(ErrorCode.AS_TPM_NOT_SUPPORTED, hostId);
        }
        if(forceVerify != true){
            //TblSamlAssertion tblSamlAssertion = new TblSamlAssertionJpaController((getEntityManagerFactory())).findByHostAndExpiry(hostId);
            //TblSamlAssertion tblSamlAssertion = My.jpa().mwSamlAssertion().findByHostAndExpiry(tblHosts.getName()); //hostId);
            TblSamlAssertionJpaController tblSamlAssertionJpa = getSamlAssertionJpaController();
            TblSamlAssertion tblSamlAssertion = tblSamlAssertionJpa.findByHostAndExpiry(tblHosts.getName());
            
            if(tblSamlAssertion != null){
                if(tblSamlAssertion.getErrorMessage() == null|| tblSamlAssertion.getErrorMessage().isEmpty()) {
                    log.debug("Found assertion in cache. Expiry time : " + tblSamlAssertion.getExpiryTs());
                    //HostAttestation ha = new HostAttestation();
                    return buildHostAttestation(tblHosts, tblSamlAssertion).getSaml();
                } else {
                    log.debug("Found assertion in cache with error set, returning that.");
                   throw new ASException(new Exception("("+ tblSamlAssertion.getErrorCode() + ") " + tblSamlAssertion.getErrorMessage() + " (cached on " + tblSamlAssertion.getCreatedTs().toString()  +")"));
                }
            }
        }
        
        log.debug("Getting trust and saml assertion from host.");
        
        try {
//            return getTrustWithSaml(tblHosts, hostId);
            return getTrustWithSaml(tblHosts, hostId, hostAttestationUuid);
        }catch(Exception e) {
            TblSamlAssertion tblSamlAssertion = new TblSamlAssertion();
            tblSamlAssertion.setAssertionUuid(hostAttestationUuid);
            tblSamlAssertion.setHostId(tblHosts);
            //TxtHost hostTxt = getHostWithTrust(new Hostname(host),tblSamlAssertion); 
            //TxtHostRecord tmp = new TxtHostRecord();
            //tmp.HostName = host;
            //tmp.IPAddress = host;
            //TxtHost hostTxt = new TxtHost(tmp);
            
            tblSamlAssertion.setBiosTrust(false);
            tblSamlAssertion.setVmmTrust(false);
            
            try {
                log.error("Caught exception, generating saml assertion");
                log.error("Printing stacktrace first");
                e.printStackTrace();
                tblSamlAssertion.setSaml("");
                int cacheTimeout=ASConfig.getConfiguration().getInt("saml.validity.seconds",3600);
                tblSamlAssertion.setCreatedTs(Calendar.getInstance().getTime());
                Calendar cal = Calendar.getInstance();
                cal.add(Calendar.SECOND, cacheTimeout);
                tblSamlAssertion.setExpiryTs(cal.getTime());
                if(e instanceof ASException){
                    ASException ase = (ASException) e;
                    log.debug("e is an instance of ASExpection: " +String.valueOf(ase.getErrorCode()));
                    tblSamlAssertion.setErrorCode(String.valueOf(ase.getErrorCode()));
                }else{
                    log.debug("e is NOT an instance of ASExpection: " +String.valueOf(ErrorCode.AS_HOST_TRUST_ERROR.getErrorCode()));
                    tblSamlAssertion.setErrorCode(String.valueOf(ErrorCode.AS_HOST_TRUST_ERROR.getErrorCode()));
                }
                // tblSamlAssertion.setErrorMessage(e.getMessage());
                // Bug fix for 1038
                tblSamlAssertion.setErrorMessage(e.getClass().getSimpleName());
                getSamlAssertionJpaController().create(tblSamlAssertion);
            }catch(Exception ex){
                //log.debug("getTrustwithSaml caugh exception while generating error saml assertion");
                log.error("getTrustwithSaml caugh exception while generating error saml assertion", ex);
                // String msg = ex.getMessage();
                String msg = ex.getClass().getSimpleName();
                // log.debug(msg);
                // throw new ASException(new Exception("getTrustWithSaml " + msg));
                throw new ASException(ex, ErrorCode.AS_HOST_TRUST_ERROR, msg);
                //throw new ASException(new Exception("Host Manifest is missing required PCRs."));
            } 
            //Daniel, change the messages into meaningful thiings here
            //log.debug("e.getMessage = "+e.getMessage());
            //throw new ASException(new Exception(e.getMessage()));
            log.error("Error during retrieval of host trust status.", e);
            throw new ASException(e, ErrorCode.AS_HOST_TRUST_ERROR, e.getClass().getSimpleName());
            //throw new ASException(new Exception("Host Manifest is missing required PCRs."));
        }
    }
    
    public TblSamlAssertionJpaController getSamlAssertionJpaController() {
	return new TblSamlAssertionJpaController(getEntityManagerFactory());
    }
    
    public HostAttestation buildHostAttestation(TblHosts tblHosts, TblSamlAssertion tblSamlAssertion) throws IOException {
        HostAttestation hostAttestation = new HostAttestation();
        //hostAttestation.setAikSha1(tblHosts.getAikSha1());
        //hostAttestation.setChallenge(tblHosts.getChallenge());
        hostAttestation.setHostName(tblHosts.getName());
        //hostAttestation.setHostUuid(tblHosts.getUuid_hex()); //.getHardwareUuid());
        hostAttestation.setId(UUID.valueOf(tblSamlAssertion.getAssertionUuid()));
        hostAttestation.setSaml(tblSamlAssertion.getSaml());
        //hostAttestation.setTrustReport(mapper.readValue(tblSamlAssertion.getTrustReport(), TrustReport.class));

        HostTrustStatus hostTrustStatus = new HostTrustStatus();
        hostTrustStatus.bios = tblSamlAssertion.getBiosTrust();
        hostTrustStatus.vmm = tblSamlAssertion.getVmmTrust();
        //hostTrustStatus.asset_tag = tblSamlAssertion.getAssetTagTrust();
        hostAttestation.setHostTrustResponse(new HostTrustResponse(new Hostname(tblHosts.getName()), hostTrustStatus));
        return hostAttestation;
    }
    
public String getTrustWithSamlForHostnames(Collection<String> hosts) throws IOException {
        //My.initDataEncryptionKey();
        ArrayList<TblHosts> tblHostsList = new ArrayList<TblHosts>();
        for(String host : hosts) {
            TblHosts tblHosts = getHostByName(new Hostname((host)));
            tblHostsList.add(tblHosts);
        }
        return getTrustWithSaml(tblHostsList);
    }
    
    /**
     * Returns a multi-host SAML assertion.  It's similar to getTrustWithSaml(TblHosts,String)
     * but it does NOT save the generated SAML assertion.
     */
    public String getTrustWithSaml(Collection<TblHosts> tblHostsCollection) {
        try {
            //String location = hostTrustBO.getHostLocation(new Hostname(hostName)).location; // example: "San Jose"
            //HostTrustStatus trustStatus = hostTrustBO.getTrustStatus(new Hostname(hostName)); // example:  BIOS:1,VMM:1
            ArrayList<TxtHostWithAssetTag> hostList = new ArrayList<>();
            
            for(TblHosts tblHosts : tblHostsCollection) {
                // these 3 lines equivalent of getHostWithTrust without a host-specific saml assertion table record to update 
                HostTrustStatus trust = getTrustStatus(tblHosts, tblHosts.getUuid_hex()); 
                TxtHostRecord data = createTxtHostRecord(tblHosts);
                TxtHost host = new TxtHost(data, trust);

                // We need to add the Asset tag related data only if the host is provisioned for it. This is done
                // by verifying in the asset tag certificate table. 
                X509AttributeCertificate tagCertificate; 
                AssetTagCertBO atagCertBO = new AssetTagCertBO();
                MwAssetTagCertificate atagCertForHost = atagCertBO.findValidAssetTagCertForHost(tblHosts.getHardwareUuid());
                if (atagCertForHost != null) {
                    tagCertificate = X509AttributeCertificate.valueOf(atagCertForHost.getCertificate());
                } else {
                    tagCertificate = null;
                }
                
                /*
                // We will check if the asset-tag was verified successfully for the host. If so, we need to retrieve
                // all the attributes for that asset-tag and send it to the saml generator.
                X509AttributeCertificate tagCertificate = null; 
                if (host.isAssetTagTrusted()) {
                    AssetTagCertBO atagCertBO = new AssetTagCertBO();
                    MwAssetTagCertificate atagCertForHost = atagCertBO.findValidAssetTagCertForHost(tblHosts.getHardwareUuid());
                    if (atagCertForHost != null) {
                        tagCertificate = X509AttributeCertificate.valueOf(atagCertForHost.getCertificate());
//                        atags.add(new AttributeOidAndValue("UUID", atagCertForHost.getUuid())); // should already be the "Subject" attribute of the certificate, if not then we need to get it from one of the cert attributes
                    }
                }*/
                
                TxtHostWithAssetTag hostWithAssetTag = new TxtHostWithAssetTag(host, tagCertificate);
                hostList.add(hostWithAssetTag);
            }
            
            SamlAssertion samlAssertion = getSamlGenerator().generateHostAssertions(hostList);

            log.debug("Expiry {}" , samlAssertion.expiry_ts.toString());

            return samlAssertion.assertion ;
        } catch (ASException e) {
            // ASException sets HTTP Status to 400 for all errors
            // We override that here to give more specific codes when possible:
            if (e.getErrorCode().equals(ErrorCode.AS_HOST_NOT_FOUND)) {
                throw new WebApplicationException(Status.NOT_FOUND);
            }
            /*
             * if( e.getErrorCode().equals(ErrorCode.TA_ERROR)) { throw new
             * WebApplicationException(Status.INTERNAL_SERVER_ERROR); }
             *
             */
            throw e;
        } catch (Exception ex) {
            // throw new ASException( e);
            log.error("Error during retrieval of host trust status.", ex);
            throw new ASException(ErrorCode.AS_HOST_TRUST_ERROR, ex.getClass().getSimpleName());
        }
        
    }
    
    public String getTrustWithSaml(TblHosts tblHosts, String hostId, String hostAttestationUuid) {
        try {
            //String location = hostTrustBO.getHostLocation(new Hostname(hostName)).location; // example: "San Jose"
            //HostTrustStatus trustStatus = hostTrustBO.getTrustStatus(new Hostname(hostName)); // example:  BIOS:1,VMM:1
                
            TblSamlAssertion tblSamlAssertion = new TblSamlAssertion();

            TxtHost host = getHostWithTrust(tblHosts, hostId,tblSamlAssertion);
            
            tblSamlAssertion.setAssertionUuid(hostAttestationUuid);
            tblSamlAssertion.setBiosTrust(host.isBiosTrusted());
            tblSamlAssertion.setVmmTrust(host.isVmmTrusted());

            // We need to add the Asset tag related data only if the host is provisioned for it. This is done
            // by verifying in the asset tag certificate table. 
            X509AttributeCertificate tagCertificate; 
            AssetTagCertBO atagCertBO = new AssetTagCertBO();
            MwAssetTagCertificate atagCertForHost = atagCertBO.findValidAssetTagCertForHost(tblSamlAssertion.getHostId().getId());
            if (atagCertForHost != null) {
                log.debug("Host has been provisioned in the system with a TAG.");
                tagCertificate = X509AttributeCertificate.valueOf(atagCertForHost.getCertificate());
            } else {
                log.debug("Host has not been provisioned in the system with a TAG.");
                tagCertificate = null;
            }

//            if (tblHosts.getBindingKeyCertificate() != null && !tblHosts.getBindingKeyCertificate().isEmpty()) {
//                host.setBindingKeyCertificate(tblHosts.getBindingKeyCertificate());
//            }
            
            SamlAssertion samlAssertion = getSamlGenerator().generateHostAssertion(host, tagCertificate, null);

            
            // We will check if the asset-tag was verified successfully for the host. If so, we need to retrieve
            // all the attributes for that asset-tag and send it to the saml generator.
/*            X509AttributeCertificate tagCertificate = null; 
            if (host.isAssetTagTrusted()) {
                AssetTagCertBO atagCertBO = new AssetTagCertBO();
                MwAssetTagCertificate atagCertForHost = atagCertBO.findValidAssetTagCertForHost(tblSamlAssertion.getHostId().getId());
                if (atagCertForHost != null) {
                    tagCertificate = X509AttributeCertificate.valueOf(atagCertForHost.getCertificate());
//                        atags.add(new AttributeOidAndValue("UUID", atagCertForHost.getUuid())); // should already be the "Subject" attribute of the certificate, if not then we need to get it from one of the cert attributes
                }
            }

            SamlAssertion samlAssertion = getSamlGenerator().generateHostAssertion(host, tagCertificate);
*/
            log.debug("Expiry {}" , samlAssertion.expiry_ts.toString());

            tblSamlAssertion.setSaml(samlAssertion.assertion);
            tblSamlAssertion.setExpiryTs(samlAssertion.expiry_ts);
            tblSamlAssertion.setCreatedTs(samlAssertion.created_ts);
            
//            TrustReport hostTrustReport = getTrustReportForHost(tblHosts, tblHosts.getName());
//            tblSamlAssertion.setTrustReport(mapper.writeValueAsString(hostTrustReport));
//            logTrustReport(tblHosts, hostTrustReport); // Need to cache the attestation report ### v1 requirement to log to mw_ta_log
                
            getSamlAssertionJpaController().create(tblSamlAssertion);

            return samlAssertion.assertion;
        } catch (ASException e) {
            // ASException sets HTTP Status to 400 for all errors
            // We override that here to give more specific codes when possible:
            if (e.getErrorCode().equals(ErrorCode.AS_HOST_NOT_FOUND)) {
                throw new WebApplicationException(Status.NOT_FOUND);
            }
            /*
             * if( e.getErrorCode().equals(ErrorCode.TA_ERROR)) { throw new
             * WebApplicationException(Status.INTERNAL_SERVER_ERROR); }
             *
             */
            throw e;
        } catch (Exception ex) {
            // throw new ASException( e);
            log.error("Error during retrieval of host trust status.", ex);
            throw new ASException(ErrorCode.AS_HOST_TRUST_ERROR, ex.getClass().getSimpleName());
        }
    }
    
    public TxtHost getHostWithTrust(TblHosts tblHosts, String hostId, TblSamlAssertion tblSamlAssertion) throws IOException {
        //HostTrustStatus trust = getTrustStatus(tblHosts, hostId);
        HostTrustStatus trust = getTrustStatus(new Hostname(tblHosts.getName()));
        TxtHostRecord data = createTxtHostRecord(tblHosts);
        TxtHost host = new TxtHost(data, trust);
        tblSamlAssertion.setHostId(tblHosts);
        tblSamlAssertion.setBiosTrust(trust.bios);
        tblSamlAssertion.setVmmTrust(trust.vmm);
        return host;
    }
    
    public HostTrustStatus getTrustStatus(TblHosts tblHosts, String hostId) throws IOException {
        if (tblHosts == null) {
            throw new ASException(
                    ErrorCode.AS_HOST_NOT_FOUND,
                    hostId);
        }
        HostTrustStatus trust = new HostTrustStatus();
        trust.asset_tag = false;
        trust.bios = false;
        trust.location = false;
        trust.vmm = false;

        return trust;
    }
    
    private SamlGenerator getSamlGenerator() throws UnknownHostException, ConfigurationException, IOException, org.opensaml.xml.ConfigurationException, ClassNotFoundException {
        org.apache.commons.configuration.Configuration conf = ASConfig.getConfiguration();
        InetAddress localhost = InetAddress.getLocalHost();
        String defaultIssuer = "https://" + localhost.getHostAddress() + ":8181/AttestationService"; 
        String issuer = conf.getString("saml.issuer", defaultIssuer);
        SamlGenerator saml = new SamlGenerator(samlKeystoreResource, conf);
        
//        if(saml != null)
//            log.info("getSamlGenerator: saml is not null");
//        else
//            log.info("getSamlGenerator: saml is null");
        
        saml.setIssuer(issuer);
        return saml;
    }
}

