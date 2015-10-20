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

import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mtwilson.util.net.Hostname;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mtwilson.agent.HostAgent;
import com.intel.mtwilson.agent.HostAgentFactory;
import com.intel.mtwilson.as.controller.TblEventTypeJpaController;
import com.intel.mtwilson.as.controller.TblHostSpecificManifestJpaController;
import com.intel.mtwilson.as.controller.TblHostsJpaController;
import com.intel.mtwilson.as.controller.TblLocationPcrJpaController;
import com.intel.mtwilson.as.controller.TblMleJpaController;
import com.intel.mtwilson.as.controller.TblModuleManifestJpaController;
import com.intel.mtwilson.as.controller.TblPackageNamespaceJpaController;
import com.intel.mtwilson.as.controller.TblPcrManifestJpaController;
import com.intel.mtwilson.as.controller.TblSamlAssertionJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.controller.exceptions.IllegalOrphanException;
import com.intel.mtwilson.as.controller.exceptions.NonexistentEntityException;
import com.intel.mtwilson.as.data.MwAssetTagCertificate;
import com.intel.mtwilson.as.data.TblEventType;
import com.intel.mtwilson.as.data.TblHostSpecificManifest;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblModuleManifest;
import com.intel.mtwilson.as.data.TblPackageNamespace;
import com.intel.mtwilson.as.data.TblSamlAssertion;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.as.helper.BaseBO;
import com.intel.mtwilson.crypto.CryptographyException;
//import com.intel.mtwilson.crypto.Sha1Digest;
import com.intel.mtwilson.util.crypto.Sha1Digest;

//import com.intel.mtwilson.crypto.X509Util;
import com.intel.mtwilson.util.x509.X509Util;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.util.model.Measurement;
import com.intel.mtwilson.util.ResourceFinder;
import com.intel.mtwilson.util.io.UUID;
import com.intel.mtwilson.util.model.PcrEventLog;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManagerFactory;
import javax.persistence.NoResultException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * All settings should be via setters, not via constructor, because this class may be instantiated by a factory.
 * 
 * @author dsmagadx
 */
public class HostBO extends BaseBO {

	private static final String COMMAND_LINE_MANIFEST = "/b.b00 vmbTrustedBoot=true tboot=0x0x101a000";
	private static final String LOCATION_PCR = "22";
        private static final String MODULE_PCR = "19";
        private Logger log = LoggerFactory.getLogger(getClass());
	private TblMle biosMleId = null;
	private TblMle vmmMleId = null;
        
	public String addHost(TxtHost host) {
		String certificate = null;
		String location = null;
		String ipAddress = null;
		HashMap<String, ? extends IManifest> pcrMap = null;
		try {
            ipAddress = InetAddress.getByName(host.getHostName().toString()).getHostAddress();
			if (!ipAddress.equalsIgnoreCase(host.getIPAddress().toString())) {
				throw new ASException(ErrorCode.AS_HOST_IPADDRESS_NOT_MATCHED, host.getHostName().toString(),host.getIPAddress().toString());
			}
			checkForDuplicate(host);
			getBiosAndVMM(host);
			log.info("Getting Server Identity.");
			TblHosts tblHosts = new TblHosts();
			tblHosts.setTlsPolicyName("TRUST_FIRST_CERTIFICATE");
			tblHosts.setTlsKeystore(null);
			tblHosts.setAddOnConnectionInfo(host.getAddOn_Connection_String());
			if (host.getHostName() != null) {
				tblHosts.setName(host.getHostName().toString());
			}
			if (host.getIPAddress() != null) {
				tblHosts.setIPAddress(host.getIPAddress().toString());
			}
			if (host.getPort() != null) {
				tblHosts.setPort(host.getPort());
			}
                        else{
                            throw new ASException(ErrorCode.PORT_MISSING, host.getHostName().toString(),host.getIPAddress().toString());
			}
                        

			if (canFetchAIKCertificateForHost(host.getVmm().getName())) { // datatype.Vmm
				if (!host.getAddOn_Connection_String().toLowerCase().contains("citrix")) {
					certificate = getAIKCertificateForHost(tblHosts, host);
					// we have to check that the aik certificate was signed by a trusted privacy ca
					X509Certificate hostAikCert = X509Util.decodePemCertificate(certificate);
					hostAikCert.checkValidity();
					// read privacy ca certificate
					InputStream privacyCaIn = new FileInputStream( ResourceFinder.getFile("PrivacyCA.cer"));
					// XXX TODO currently we only support one privacy CA cert...
					// in the future we should read a PEM format file with possibly multiple trusted privacy ca certs
					X509Certificate privacyCaCert = X509Util.decodeDerCertificate(IOUtils.toByteArray(privacyCaIn));
					IOUtils.closeQuietly(privacyCaIn);
					privacyCaCert.checkValidity();
					// verify the trusted privacy ca signed this aik cert
					hostAikCert.verify(privacyCaCert.getPublicKey()); 
					// NoSuchAlgorithmException,InvalidKeyException,NoSuchProviderException,SignatureException
				}
			} else {
				// ESX host so get the location for the host and store in the table
				pcrMap = getHostPcrManifest(tblHosts, host);
                                
				// BUG #497 sending both the new TblHosts record and the TxtHost object just to get the TlsPolicy into
				// the initial call so that with the trust_first_certificate policy we will obtain the host certificate now while adding it
				log.info("Getting location for host from VCenter");
				location = getLocation(pcrMap);
			}
                        
                                                
                        HostAgentFactory factory = new HostAgentFactory();
                        HostAgent agent = factory.getHostAgent(tblHosts);
			log.info("Saving Host in database with TlsPolicyName {} and TlsKeystoreLength {}",tblHosts.getTlsPolicyName(),tblHosts.getTlsKeystore() == null ? "null" : tblHosts.getTlsKeystore().length);
                        Map<String,String> attributes = agent.getHostAttributes();
                        String hostUuidAttr = attributes.get("Host_UUID");
                        //if ((attributes != null) && (!attributes.isEmpty()) && (hostUuidAttr != null))
                        if (!attributes.isEmpty() && hostUuidAttr != null)
                            tblHosts.setHardwareUuid(hostUuidAttr.toLowerCase().trim());
//                        
			log.debug("Saving the host details in the DB");
                        
                        // retrieve the complete manifest and get module info inserted into database
                        // We only handle module info for PCR 19
			HashMap<String, ? extends IManifest> pcrs = getHostPcrManifest(tblHosts, host);
                        List<TblHostSpecificManifest> tblHostSpecificManifests = null;
                        
                        if(vmmMleId.getRequiredManifestList().contains(MODULE_PCR)) {
                            if (pcrs != null) {
                                PcrManifest pcr19 = (PcrManifest) pcrs.get(MODULE_PCR);
                                addModuleWhiteList(pcr19, tblHosts, host, hostUuidAttr);

                                log.info("Host specific modules would be retrieved from the host that extends into PCR 19.");
                                String hostType = host.getVendor();
                                tblHostSpecificManifests = createHostSpecificManifestRecords(vmmMleId, pcrs, hostType);
                            }
                        }
                        else {
                            log.info("Host specific modules will not be configured since PCR 19 is not selected for attestation");
                        }
                        
			//saveHostInDatabase(tblHosts, host, certificate, location, pcrMap);
                        biosMleId = findBiosMleForHost(host); 
                        vmmMleId = findVmmMleForHost(host); 
                        saveHostInDatabase(tblHosts, host, certificate, location, pcrMap, tblHostSpecificManifests, biosMleId, vmmMleId);
                        
                         // Now that the host has been registered successfully, let us see if there is an asset tag certificated configured for the host
                        // to which the host has to be associated
                        associateAssetTagCertForHost(host, agent.getHostAttributes(), tblHosts); //attributes);
                        

		} catch (ASException ase) {
			throw ase;
		} catch (CryptographyException e) {
			throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
		} catch (Exception e) {
			log.debug("beggining stack trace --------------");
			e.printStackTrace();
			log.debug("end stack trace --------------");
			throw new ASException(e);
		}
		return "true";
	}

	private String getLocation(HashMap<String, ? extends IManifest> pcrMap) {

		if (pcrMap != null) {// Pcr map will be null for host which dont support TPM
			
			if(pcrMap.containsKey(LOCATION_PCR))
				return new TblLocationPcrJpaController(getEntityManagerFactory())
					.findTblLocationPcrByPcrValue(((PcrManifest) pcrMap.get(LOCATION_PCR)).getPcrValue());
		}

		return null;
	}

	// BUG #497 adding TblHosts parameter to this call so we can send the TlsPolicy to the HostAgentFactory for making the connection
	private HashMap<String, ? extends IManifest> getHostPcrManifest(
			TblHosts tblHosts, TxtHost host) {
		try {

			// bug #538 check the host capability before we try to get a manifest
			HostAgent agent = getHostAgent(tblHosts);
			if (agent.isTpmAvailable()) {

				HashMap<String, ? extends IManifest> pcrMap = getPcrModuleManifestMap(tblHosts, host);
				return pcrMap;
			} else {
				throw new ASException(ErrorCode.AS_VMW_TPM_NOT_SUPPORTED, tblHosts.getName());
			}

		} catch (ASException e) {
			if (!e.getErrorCode().equals(ErrorCode.AS_VMW_TPM_NOT_SUPPORTED)) {
				throw e;
			} else {
				log.info("VMWare host does not support TPM. Ignoring the error for now");
			}
			return null;
		}
	}

        
	private HashMap<String, ? extends IManifest> getPcrModuleManifestMap( TblHosts tblHosts, TxtHost host) {

		HostAgentFactory hostAgentFactory = getHostAgentFactory();
		HashMap<String, ? extends IManifest> pcrMap = hostAgentFactory.getManifest(tblHosts);
		return pcrMap;
	}

	private boolean canFetchAIKCertificateForHost(String vmmName) {
		return (!vmmName.contains("ESX"));
	}
        
        /**
     * 
     * @param host 
     */
    private void associateAssetTagCertForHost(TxtHost host, Map<String, String> hostAttributes, TblHosts tblHost) {
        String hostUUID;
        
        try {
            log.debug("Starting the procedure to map the asset tag certificate for host {}.", host.getHostName().toString());
            
            // First let us find if the asset tag is configured for this host or not. This information
            // would be available in the mw_asset_tag_certificate table, where the host's UUID would be
            // present.
            if (hostAttributes != null && hostAttributes.containsKey("Host_UUID")) {
                hostUUID = hostAttributes.get("Host_UUID");
            } else {
                log.info("Since UUID for the host {} is not specified, asset tag would not be configured.", host.getHostName().toString());
                return;
            }
            
            // Now that we have a valid host UUID, let us search for an entry in the db.
            AssetTagCertBO atagCertBO = new AssetTagCertBO();
            MwAssetTagCertificate atagCert = atagCertBO.findValidAssetTagCertForHost(hostUUID);
            if (atagCert != null) {
                log.debug("Found a valid asset tag certificate for the host {} with UUID {}.", host.getHostName().toString(), hostUUID);
                // Now that there is a asset tag certificate for the host, let us retrieve the host ID and update
                // the asset tag certificate with that ID
                //TblHosts tblHost = My.jpa().mwHosts().findByName(host.getHostName().toString());
                if (tblHost != null) {
                    AssetTagCertAssociateRequest atagMapRequest = new AssetTagCertAssociateRequest();
                    atagMapRequest.setSha1OfAssetCert(atagCert.getSHA1Hash());
                    atagMapRequest.setHostID(tblHost.getId());
                    
                    boolean mapAssetTagCertToHost = atagCertBO.mapAssetTagCertToHostById(atagMapRequest);
                    if (mapAssetTagCertToHost)
                        log.info("Successfully mapped the asset tag certificate with UUID {} to host {}", atagCert.getUuid(), tblHost.getName());
                    else
                        log.info("No valid asset tag certificate configured for the host {}.", tblHost.getName());
                }
            } else {
                log.info("No valid asset tag certificate configured for the host {}.", host.getHostName().toString());
            }
            
        } catch (Exception ex) {
            // Log the error and return back.
            log.info("Error during asset tag configuration for the host {}. Details: {}.", host.getHostName().toString(), ex.getMessage());
        }
        
    }

	public String updateHost(TxtHost host) {

		try {

			TblHosts tblHosts = getHostByName(host.getHostName()); // datatype.Hostname
			if (tblHosts == null) {
				throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, host
						.getHostName().toString());
			}

			getBiosAndVMM(host);

			// need to update with the new connection string before we attempt to connect to get any updated info from 
			//host (aik cert, manifest,etc)
			if (tblHosts.getTlsPolicyName() == null && tblHosts.getTlsPolicyName().isEmpty()) {
				// XXX new code to test
				tblHosts.setTlsPolicyName("TRUST_FIRST_CERTIFICATE");
				// XXX bug #497 the TxtHost object doesn't have the ssl
				// certificate and policy
			}
			tblHosts.setAddOnConnectionInfo(host.getAddOn_Connection_String());
			if (host.getHostName() != null) {
				tblHosts.setName(host.getHostName().toString());
			}
			if (host.getIPAddress() != null) {
				tblHosts.setIPAddress(host.getIPAddress().toString());
			}
			if (host.getPort() != null) {
				tblHosts.setPort(host.getPort());
			}

			log.info("Getting identity.");
			if (canFetchAIKCertificateForHost(host.getVmm().getName())) { // datatype.Vmm
				String certificate = getAIKCertificateForHost(tblHosts, host);
				tblHosts.setAIKCertificate(certificate);
			} else { // ESX host so get the location for the host and store in
						// the
				if (vmmMleId.getId().intValue() != tblHosts.getVmmMleId().getId().intValue()) {
					log.info("VMM is updated. Update the host specific manifest");
					// BUG #497 added tblHosts parameter
					HashMap<String, ? extends IManifest> pcrMap = getHostPcrManifest( tblHosts, host);
					// Building objects and validating that manifests are
					// created ahead of create of host
				}
			}
                        
                        List<TblHostSpecificManifest> tblHostSpecificManifests = null;
                        
                        if(vmmMleId.getId().intValue() != tblHosts.getVmmMleId().getId().intValue() ) {
                            log.info("VMM is updated. Update the host specific manifest");
                            HashMap<String, ? extends IManifest> pcrs = getHostPcrManifest(tblHosts, host);
                            
                            deleteHostSpecificManifest(tblHosts);
                            
                            //We need to check if the white list configured for the MLE requires PCR 19. If not, we will skip creating the host specific modules.
                            
                            if(vmmMleId.getRequiredManifestList().contains(MODULE_PCR)) {
                                log.debug("Host specific modules would be retrieved from the host that extends into PCR 19.");
                                // Added the Vendor parameter to the below function so that we can handle the host specific records differently for different types of hosts.
                                String hostType = host.getVendor();
                                tblHostSpecificManifests = createHostSpecificManifestRecords(vmmMleId, pcrs, hostType);
                            } else {
                                log.debug("Host specific modules will not be configured since PCR 19 is not selected for attestation");
                            }
                        }
                        
                        biosMleId = findBiosMleForHost(host); 
                        vmmMleId = findVmmMleForHost(host); 

			log.info("Saving Host in database");
			tblHosts.setBiosMleId(biosMleId);
			tblHosts.setDescription(host.getDescription());
			tblHosts.setEmail(host.getEmail());
			if (host.getIPAddress() != null)
				tblHosts.setIPAddress(host.getIPAddress().toString()); // datatype.IPAddress
			tblHosts.setPort(host.getPort());
			tblHosts.setVmmMleId(vmmMleId);
                        
                        tblHosts.setBios_mle_uuid_hex(biosMleId.getUuid_hex());
                        tblHosts.setVmm_mle_uuid_hex(vmmMleId.getUuid_hex());
                        

			log.info("Updating Host in database");
			getHostsJpaController().edit(tblHosts);
                        
                        if(tblHostSpecificManifests != null) {
                            log.debug("Updating Host Specific Manifest in database");
                            createHostSpecificManifest(tblHostSpecificManifests, tblHosts);
                        }

		} catch (ASException ase) {
			throw ase;
		} catch (CryptographyException e) {
			throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR,
					e.getCause() == null ? e.getMessage() : e.getCause()
							.getMessage());
		} catch (Exception e) {
			throw new ASException(e);
		}

		// return new HostResponse(ErrorCode.OK);
		return "true";
	}

	public String deleteHost(Hostname hostName) { // datatype.Hostname

		try {
			TblHosts tblHosts = getHostByName(hostName);
			if (tblHosts == null) {
				throw new ASException(ErrorCode.AS_HOST_NOT_FOUND, hostName);
			}
			log.info("Deleting Host from database");
                        deleteHostAssetTagMapping(tblHosts);
                        deleteHostSpecificManifest(tblHosts);
                        deleteModulesForMLE(createTxtHostFromDatabaseRecord(tblHosts));
			deleteTALogs(tblHosts.getId());
                        deleteSAMLAssertions(tblHosts);

			getHostsJpaController().destroy(tblHosts.getId());
                        unmapAssetTagCertFromHost(tblHosts.getId(), tblHosts.getName());
		} catch (ASException ase) {
			throw ase;
		} catch (CryptographyException e) {
			throw new ASException(ErrorCode.SYSTEM_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage(), e);
		} catch (Exception e) {
			throw new ASException(e);
		}
		// return new HostResponse(ErrorCode.OK);
		return "true";
	}
        
     // PREMIUM FEATURE ? 
        private void deleteHostSpecificManifest(TblHosts tblHosts) throws NonexistentEntityException, IOException {
                //TblHostSpecificManifestJpaController tblHostSpecificManifestJpaController = My.jpa().mwHostSpecificManifest();
            
                TblHostSpecificManifestJpaController tblHostSpecificManifestJpaController = getHostSpecificManifestJpaController();
                
                for(TblModuleManifest moduleManifest : tblHosts.getVmmMleId().getTblModuleManifestCollection()) {
                     if( moduleManifest.getUseHostSpecificDigestValue() != null && moduleManifest.getUseHostSpecificDigestValue().booleanValue() ) {
                        // For open source we used to have multiple module manifests for the same hosts. So, the below query by hostID was returning multiple results.
                        TblHostSpecificManifest hostSpecificManifest = tblHostSpecificManifestJpaController.findByModuleAndHostID(tblHosts.getId(), moduleManifest.getId());
                        if (hostSpecificManifest != null) {
                                log.debug("Deleting Host specific manifest." + moduleManifest.getComponentName() + ":" + hostSpecificManifest.getDigestValue());
                                tblHostSpecificManifestJpaController.destroy(hostSpecificManifest.getId());
                        }                        
                    }
                }                
        }
        
        private void deleteModulesForMLE(TxtHostRecord host) throws NonexistentEntityException, IOException {
            
            TblMleJpaController tblMleJpaController  = getMleJpaController();
            TblModuleManifestJpaController tblModuleManifestJpaController = getModuleJpaController();
            
            try {
                TblMle tblMle = tblMleJpaController.findVmmMle(host.VMM_Name, host.VMM_Version, host.VMM_OSName, host.VMM_OSVersion);
                
                if (tblMle != null) {
                    
                    // Retrieve the list of all the modules for the specified VMM MLE.
                    List<TblModuleManifest> moduleList = tblModuleManifestJpaController.findTblModuleManifestByHardwareUuid(host.Hardware_Uuid);
                    if (moduleList != null && moduleList.size() > 0) {
                        for (TblModuleManifest moduleObj : moduleList) {
                            //if (moduleObj.getUseHostSpecificDigestValue()) // we cannot delete the host specific one since it would be referenced by the Hosts
                            //    continue;
                            tblModuleManifestJpaController.destroy(moduleObj.getId());
                        }
                    }
                }

            
            } catch (IllegalOrphanException | NonexistentEntityException ex) {
                log.error("Error during the deletion of VMM modules {}. ", host.VMM_Name, ex);
                throw new ASException(ErrorCode.WS_MODULE_WHITELIST_DELETE_ERROR, ex.getClass().getSimpleName());
            }          
        }
        
       
	private void deleteTALogs(Integer hostId) throws IllegalOrphanException {

		TblTaLogJpaController tblTaLogJpaController = getTaLogJpaController();

		List<TblTaLog> taLogs = tblTaLogJpaController.findLogsByHostId(hostId, new Date());

		if (taLogs != null) {

			for (TblTaLog taLog : taLogs) {
				try {
					tblTaLogJpaController.destroy(taLog.getId());
				} catch (NonexistentEntityException e) {
					log.warn("Ta Log is already deleted " + taLog.getId());
				}
			}
			log.info("Deleted all the logs for the given host " + hostId);
		}

	}
        
        /**
         * Deletes all the SAML assertions for the specified host. This should
         * be called before deleting the host.
         *
         * @param hostId
         */
        private void deleteSAMLAssertions(TblHosts hostId) throws IOException {
            
                TblSamlAssertionJpaController samlJpaController = getSamlAssertionJpaController();

		List<TblSamlAssertion> hostSAMLAssertions = samlJpaController.findByHostID(hostId);

                if (hostSAMLAssertions != null) {
                        for (TblSamlAssertion hostSAML : hostSAMLAssertions) {
                                try {
                                        samlJpaController.destroy(hostSAML.getId());
                                } catch (NonexistentEntityException e) {
                                        log.error("Ta Log is already deleted " + hostSAML.getId());
                                }
                        }
                        log.info("Deleted all the logs for the given host " + hostId);
                }
        }
        
        private void deleteHostAssetTagMapping(TblHosts tblHosts) throws NonexistentEntityException, IOException {
            AssetTagCertAssociateRequest atagRequest = new AssetTagCertAssociateRequest();
            atagRequest.setHostID(tblHosts.getId());
            AssetTagCertBO atagBO = new AssetTagCertBO();
            atagBO.unmapAssetTagCertFromHostById(atagRequest);            
        }
        
            /**
     * 
     * @param id
     * @param name 
     */
        private void unmapAssetTagCertFromHost(Integer id, String name) {
            try {
                log.debug("Starting the procedure to unmap the asset tag certificate from host {}.", name);
                        
                AssetTagCertBO atagCertBO = new AssetTagCertBO();
                AssetTagCertAssociateRequest atagUnmapRequest = new AssetTagCertAssociateRequest();
                atagUnmapRequest.setHostID(id);
                    
                boolean unmapAssetTagCertFromHost = atagCertBO.unmapAssetTagCertFromHostById(atagUnmapRequest);
                if (unmapAssetTagCertFromHost)
                    log.info("Either the asset tag certificate was successfully unmapped from the host {} or there was not asset tag certificate associated.", name);
                else
                    log.info("Either there were errors or no asset tag certificate was configured for the host {}.", name);
            
            } catch (Exception ex) {
                // Log the error and return back.
                log.info("Error during asset tag unmapping for the host {}. Details: {}.", name, ex.getMessage());
            }
        }
        

	private String getAIKCertificateForHost(TblHosts tblHosts, TxtHost host) {
		HostAgent agent = getHostAgent(tblHosts);
		if( agent.isAikAvailable() ) {
		    X509Certificate cert = agent.getAikCertificate();
		    try {
                return X509Util.encodePemCertificate(cert);
		    }
		    catch(Exception e) {
                log.error("Cannot encode AIK certificate: "+e.toString(), e);
                return null;
		    }
        }
        return null;
	}


	private void getBiosAndVMM(TxtHost host) {
		TblMleJpaController mleController = getMleJpaController();
		this.biosMleId = mleController.findBiosMle(host.getBios().getName(),
				host.getBios().getVersion(), host.getBios().getOem());
		if (biosMleId == null) {
                       throw new ASException(ErrorCode.AS_BIOS_INCORRECT, host.getBios().getName(),host.getBios().getVersion(),host.getBios().getOem());
		}
		this.vmmMleId = mleController.findVmmMle(host.getVmm().getName(), host
				.getVmm().getVersion(), host.getVmm().getOsName(), host
				.getVmm().getOsVersion());
		if (vmmMleId == null) {
                       throw new ASException(ErrorCode.AS_VMM_INCORRECT, host.getVmm().getName(),host.getVmm().getVersion(),host.getVmm().getOsName(),host.getVmm().getOsVersion());
		}
	}
        
        private TblMle findBiosMleForHost(TxtHost host) throws IOException {
            
                TblMleJpaController tblMleJpaController  = getMleJpaController();
                TblMle biosMleId = tblMleJpaController.findBiosMle(host.getBios().getName(),host.getBios().getVersion(), host.getBios().getOem());
		if (biosMleId == null) {
			throw new ASException(ErrorCode.AS_BIOS_INCORRECT, host.getBios().getName(),host.getBios().getVersion());
		}
                return biosMleId;
	}
        
	private TblMle findVmmMleForHost(TxtHost host) throws IOException {
            
                TblMleJpaController tblMleJpaController  = getMleJpaController();
		TblMle vmmMleId = tblMleJpaController.findVmmMle(host.getVmm().getName(), host.getVmm().getVersion(), host.getVmm().getOsName(), host.getVmm().getOsVersion());
		if (vmmMleId == null) {
			throw new ASException(ErrorCode.AS_VMM_INCORRECT, host.getVmm().getName(),host.getVmm().getVersion());
		}
        return vmmMleId;
	}

        
	private void saveHostInDatabase(TblHosts newRecordWithTlsPolicyAndKeystore,TxtHost host, String certificate, String location, HashMap<String, ? extends IManifest> pcrMap, List<TblHostSpecificManifest> tblHostSpecificManifests, TblMle biosMleId, TblMle vmmMleId) throws CryptographyException, IOException {

		// Building objects and validating that manifests are created ahead of create of host
		TblHosts tblHosts = newRecordWithTlsPolicyAndKeystore; // new TblHosts();
		log.info(
				"saveHostInDatabase with tls policy {} and keystore size {}",
				tblHosts.getTlsPolicyName(),
				tblHosts.getTlsKeystore() == null ? "null" : tblHosts
						.getTlsKeystore().length);
		log.error(
				"saveHostInDatabase with tls policy {} and keystore size {}",
				tblHosts.getTlsPolicyName(),
				tblHosts.getTlsKeystore() == null ? "null" : tblHosts
						.getTlsKeystore().length);

		TblHostsJpaController hostController = getHostsJpaController();
		tblHosts.setAddOnConnectionInfo(host.getAddOn_Connection_String());
		tblHosts.setBiosMleId(biosMleId);
		tblHosts.setDescription(host.getDescription());
		tblHosts.setEmail(host.getEmail());
		if (host.getIPAddress() != null) {
			tblHosts.setIPAddress(host.getIPAddress().toString()); // datatype.IPAddress
		}
		tblHosts.setName(host.getHostName().toString()); // datatype.Hostname

		if (host.getPort() != null) {
			tblHosts.setPort(host.getPort());
		}
		tblHosts.setVmmMleId(vmmMleId);
		tblHosts.setAIKCertificate(certificate); // null is ok

		if (location != null) {
			tblHosts.setLocation(location);
		}
                
                tblHosts.setBios_mle_uuid_hex(biosMleId.getUuid_hex());
                tblHosts.setVmm_mle_uuid_hex(vmmMleId.getUuid_hex());
                tblHosts.setUuid_hex(new UUID().toString());

		// create the host
		log.debug("COMMITING NEW HOST DO DATABASE");
		hostController.create(tblHosts);
                log.debug("Save host specific manifest if any");
                createHostSpecificManifest(tblHostSpecificManifests, tblHosts);

	}
        
        
        
        private List<TblHostSpecificManifest> createHostSpecificManifestRecords(TblMle vmmMleId, HashMap<String, ? extends IManifest> pcrManifest, String hostType) throws IOException {
            List<TblHostSpecificManifest> tblHostSpecificManifests = new ArrayList<>();
            
            if(vmmMleId.getRequiredManifestList().contains(MODULE_PCR) && pcrManifest !=null)
            {
                PcrManifest pcrMf19 = (PcrManifest) pcrManifest.get(MODULE_PCR);
                if(pcrMf19.containsPcrEventLog(19))
                {
                   PcrEventLog pcrEventLog = pcrMf19.getPcrEventLog(19); 
                   if(pcrEventLog != null)
                   {
                       for(Measurement m : pcrEventLog.getEventLog()) {
                           if(m != null && m.getInfo() != null && (!m.getInfo().isEmpty())) {
                               
                               m.getInfo().get("EventName");
                               m.getInfo().get("ComponentName");
                               
                               if(hostType.equals("intel") && m.getInfo().get("EventName") != null) {
                                   log.debug("Adding host specific manifest for event " + m.getInfo().get("EventName") + ": field=" + m.getLabel() + " component=" + m.getInfo().get("ComponentName"));
                                   log.debug("Querying manifest for event: " + m.getInfo().get("EventName") + ": MLE_ID=" + vmmMleId.getId() + " component=" + m.getInfo().get("ComponentName"));
                                   
                                   // For open source XEN and KVM both the modules that get extended to PCR 19 should be added into the host specific table
                                   
                                    //TblModuleManifest tblModuleManifest = My.jpa().mwModuleManifest().findByMleNameEventName(vmmMleId.getId(), m.getInfo().get("ComponentName"),  m.getInfo().get("EventName"));
                                    TblModuleManifestJpaController tblModuleManifestJpaController = getModuleJpaController();
                                    TblModuleManifest tblModuleManifest = tblModuleManifestJpaController.findByMleNameEventName(vmmMleId.getId(), m.getInfo().get("ComponentName"), m.getInfo().get("EventName"));
                                    
                                    TblHostSpecificManifest tblHostSpecificManifest = new TblHostSpecificManifest();
                                    tblHostSpecificManifest.setDigestValue(m.getValue().toString());
                                    tblHostSpecificManifest.setModuleManifestID(tblModuleManifest);
                                    tblHostSpecificManifests.add(tblHostSpecificManifest);
                               }
                           }
                       }
                   }
                    
                }
                else {
                    log.warn("No PCR 19 found.SO not saving host specific manifest.");
                }
            }
            else {
                log.warn("It is not possible to get PCR 19 info. Unable to perform database insertion");
            }
            
            return tblHostSpecificManifests;
        }
        
        private void createHostSpecificManifest(List<TblHostSpecificManifest> tblHostSpecificManifests, TblHosts tblHosts) throws IOException {
            if(tblHostSpecificManifests != null && !tblHostSpecificManifests.isEmpty()) {
                for(TblHostSpecificManifest tblHostSpecificManifest : tblHostSpecificManifests)
                {
                    tblHostSpecificManifest.setHostID(tblHosts.getId());
                    TblHostSpecificManifestJpaController tblHostSpecificManifestJpaController  = getHostSpecificManifestJpaController();
                    tblHostSpecificManifestJpaController.create(tblHostSpecificManifest);
                }
                
            }
        }
        
        private void addModuleWhiteList(PcrManifest pcr19, TblHosts tblHosts, TxtHost host, String uuid) {
        try {
            TblModuleManifestJpaController tblModuleManifestJpa = getModuleJpaController();
            TblMleJpaController tblMleJpa = getMleJpaController();
            TblEventTypeJpaController tblEventJpa = getEventJpaController();
            TblPackageNamespaceJpaController tblPackageJpa = getPackageJpaController();
            TblEventType tblEvent;
            TblMle tblMle = tblMleJpa.findTblMleByUUID(uuid);
            TblPackageNamespace nsPackNS;

            if (tblMle == null) {
                try {
                    // First check if the entry exists in the MLE table.
                    tblMle = getMleDetails(host.getVmm().getName(),
                            host.getVmm().getVersion(),
                            host.getVmm().getOsName(),
                            host.getVmm().getOsVersion(),
                            "");

                } catch (NoResultException nre) {
                    throw new ASException(nre, ErrorCode.WS_MLE_DOES_NOT_EXIST, host.getVmm().getName(), host.getVmm().getVersion());
                }
            }

            if (tblMle == null) {
                log.error("MLE specified is not found in the DB");
                throw new ASException(ErrorCode.WS_MLE_RETRIEVAL_ERROR, this.getClass().getSimpleName());
            }

            String eventName;
            String componentName;
//            String fullComponentName = "";
            String fullComponentName;
            String digest;
            String packageName;
            String packageVendor;
            String packageVersion;
            String extendedtoPCR;
            boolean useHostSpecificDigest;
            try {
                // Before we insert the record, we need the identity for the event name               
                if (pcr19.containsPcrEventLog(19)) {
                    PcrEventLog pcrEventLog = pcr19.getPcrEventLog(19);
                    if (pcrEventLog != null) {
                        for (Measurement m : pcrEventLog.getEventLog()) {
                            extendedtoPCR = m.getInfo().get("ExtendedToPCR");
                            if (extendedtoPCR != null){
                                if (extendedtoPCR.equals("19")) {
                                    //tblEvent = tblEventJpa.findEventTypeByName(m.getInfo().get("EventName"));
                                    eventName = m.getInfo().get("EventName");
                                    componentName = m.getInfo().get("ComponentName");
                                    packageName = String.valueOf(m.getInfo().get("PackageName"));
                                    packageVendor = String.valueOf(m.getInfo().get("PackageVendor"));
                                    packageVersion = String.valueOf(m.getInfo().get("PackageVersion"));
                                    extendedtoPCR = String.valueOf(m.getInfo().get("ExtendedToPCR"));
                                    digest = String.valueOf(m.getValue());
                                    useHostSpecificDigest = Boolean.valueOf(m.getInfo().get("UseHostSpecificDigest"));
                                    try {
                                        // Before we insert the record, we need the identity for the event name
                                        tblEvent = tblEventJpa.findEventTypeByName(eventName);

                                    } catch (NoResultException nre) {
                                        throw new ASException(nre, ErrorCode.WS_EVENT_TYPE_DOES_NOT_EXIST, eventName);
                                    }
                                    validateNull("EventName", eventName);
                                    validateNull("ComponentName", componentName);
                                    // For Open Source hypervisors, we do not want to prefix the event type field name. So, we need to check if the event name
                                    // corresponds to VMware, then we will append the event type fieldName to the component name. Otherwise we won't
                                    if (eventName.contains("Vim25")) {
                                        fullComponentName = tblEvent.getFieldName() + "." + componentName;
                                    } else {
                                        fullComponentName = componentName;
                                    }
                                    Integer componentID = tblModuleManifestJpa.findByMleIdEventId(tblMle.getId(), fullComponentName, tblEvent.getId());
                                    if (componentID != null && componentID != 0) {
                                        throw new ASException(ErrorCode.WS_MODULE_WHITELIST_ALREADY_EXISTS, componentName);
                                    }

                                    try {

                                        // Since there will be only one entry for now, we will just hardcode it for now.
                                        // TO-DO: See if we can change this.
                                        // Nov-12,2013: Changed to use the function that accepts the ID instead of the name for better
                                        // performance.
                                        nsPackNS = tblPackageJpa.findByName("Standard_Global_NS");

                                    } catch (NoResultException nre) {
                                        throw new ASException(ErrorCode.WS_NAME_SPACE_DOES_NOT_EXIST);
                                    }

                                    TblModuleManifest newModuleRecord = new TblModuleManifest();
                                    if (uuid != null && !uuid.isEmpty()) {
                                        newModuleRecord.setUuid_hex(uuid);
                                    } else {
                                        newModuleRecord.setUuid_hex(new UUID().toString());
                                    }
                                    newModuleRecord.setMleId(tblMle);
                                    newModuleRecord.setMle_uuid_hex(tblMle.getUuid_hex());
                                    newModuleRecord.setEventID(tblEvent);
                                    newModuleRecord.setNameSpaceID(nsPackNS);
                                    newModuleRecord.setComponentName(fullComponentName);
                                    newModuleRecord.setDigestValue(digest);
                                    newModuleRecord.setPackageName(packageName);
                                    newModuleRecord.setPackageVendor(packageVendor);
                                    newModuleRecord.setPackageVersion(packageVersion);
                                    newModuleRecord.setUseHostSpecificDigestValue(useHostSpecificDigest);
                                    newModuleRecord.setExtendedToPCR(extendedtoPCR);
                                    newModuleRecord.setDescription("");
                                    tblModuleManifestJpa.create(newModuleRecord);
//                                    break;
                                }
                            }
                        }
                    }
                }
            } catch (NoResultException nre) {
                throw new ASException(nre, ErrorCode.WS_EVENT_TYPE_DOES_NOT_EXIST);
            }

            
        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
//                    throw new ASException(ErrorCode.SYSTEM_ERROR, "Exception while adding Module white list data. " + e.getMessage(), e);
            // throw new ASException(e);
            log.error("Error during Module whitelist creation.", e);
            throw new ASException(ErrorCode.WS_MODULE_WHITELIST_CREATE_ERROR, e.getClass().getSimpleName());
        }
    }
            
               
        /**
        *
        * @param mleName
        * @param mleVersion
        * @param osName
        * @param osVersion
        * @param oemName
        * @return
        */
        private TblMle getMleDetails(String mleName, String mleVersion, String osName, String osVersion, String oemName) {
            TblMle tblMle;
            validateNull("mleName", mleName);
            validateNull("mleVersion", mleVersion);
            validateMleExtraAttributes(osName, osVersion, oemName);
            
            TblMleJpaController tblMleJpa = getMleJpaController();
            if (StringUtils.isNotBlank(oemName)) {
                log.info("Getting BIOS MLE from database");
                tblMle = tblMleJpa.findBiosMle(mleName, mleVersion, oemName);
            } else {
                log.info("Get VMM MLE from database");
                tblMle = tblMleJpa.findVmmMle(mleName, mleVersion, osName, osVersion);
            }
            return tblMle;
        }
        
         /**
        *
        * @param label
        * @param input
        * @return
        */
        private String validateNull(String label, String input) {
            if (input == null || input.isEmpty()) {
                // log.debug(String.format("Required input parameter '%s' is null or missing.", label));
                log.debug("Required input parameter {} is null or missing.", label);
                throw new ASException(ErrorCode.WS_MLE_DATA_MISSING, label);
            }
            return input;
        }
        
        /**
        *
        * @param osName
        * @param osVersion
        * @param oemName
        */
        private void validateMleExtraAttributes(String osName, String osVersion, String oemName) {
            if (StringUtils.isNotBlank(oemName)) {
                if ((StringUtils.isNotBlank(osName) || StringUtils.isNotBlank(osVersion))) {
                    throw new ASException(ErrorCode.WS_OEM_OS_DATA_CANNOT_COEXIST);
                }
            } else if (StringUtils.isBlank(osName) || StringUtils.isBlank(osVersion)) {
                throw new ASException(ErrorCode.WS_MLE_DATA_MISSING, "OEM/OS");
            }

        }


	public HostResponse isHostRegistered(String hostnameOrAddress) {
		try {
			TblHostsJpaController tblHostsJpaController = new TblHostsJpaController(
					getEntityManagerFactory());
			TblHosts tblHosts = tblHostsJpaController
					.findByName(hostnameOrAddress);
			if (tblHosts != null) {
				return new HostResponse(ErrorCode.OK); // host name exists in database
			}
			tblHosts = tblHostsJpaController.findByIPAddress(hostnameOrAddress);
			if (tblHosts != null) {
				return new HostResponse(ErrorCode.OK); // host IP address exists in database
			}
			return new HostResponse(ErrorCode.AS_HOST_NOT_FOUND);
		} catch (ASException e) {
			throw e;
		} catch (Exception e) {
			throw new ASException(e);
		}
	}

	private void checkForDuplicate(TxtHost host) throws CryptographyException {
		TblHostsJpaController tblHostsJpaController = getHostsJpaController();
		TblHosts tblHosts1 = tblHostsJpaController.findByName(host.getHostName()
				.toString()); // datatype.Hostname
		TblHosts tblHosts2 = tblHostsJpaController.findByIPAddress(host.getIPAddress()
				.toString());
		if (tblHosts1 != null) {
			throw new ASException(
					ErrorCode.AS_HOST_EXISTS,
					host.getHostName());
		}
		if (tblHosts2 != null) {
			throw new ASException(
				ErrorCode.AS_IPADDRESS_EXISTS,
				host.getIPAddress().toString());
		}
	}

	/**
	 * This is not a REST API method, it is public because it is used by
	 * HostTrustBO.
	 * 
	 * @param hostName
	 * @return
	 * @throws CryptographyException
	 */
	public TblHosts getHostByName(Hostname hostName) throws CryptographyException { // datatype.Hostname
           TblHosts tblHosts = new TblHosts();
           try {
              InetAddress addr = InetAddress.getByName(hostName.toString());
              String hostname = addr.getHostName();
              String ip =  addr.getHostAddress();
              tblHosts = new TblHostsJpaController(getEntityManagerFactory()).findByName(hostname);
              tblHosts = tblHosts!=null? tblHosts :new TblHostsJpaController(getEntityManagerFactory()).findByName(ip);
           } catch (UnknownHostException e) {
              log.error("Unknown host", e);
           }
           return tblHosts;
	}

 	public TblHosts getHostByIpAddress(String ipAddress) throws CryptographyException {
		TblHosts tblHosts = new TblHostsJpaController(getEntityManagerFactory())
				.findByIPAddress(ipAddress);
		return tblHosts;
	}

        /**
         * Author: Sudhir
         * 
         * Searches for the hosts using the criteria specified.
         * 
         * @param searchCriteria: If in case the user has not provided any search criteria, then all the hosts
         * would be returned back to the caller
         * @return 
         */
	public List<TxtHostRecord> queryForHosts(String searchCriteria) {
		          try {
                TblHostsJpaController tblHostsJpaController = new TblHostsJpaController(
                        getEntityManagerFactory());
                List<TxtHostRecord> txtHostList = new ArrayList<TxtHostRecord>();
                List<TblHosts> tblHostList;

                if (searchCriteria != null && !searchCriteria.isEmpty()) {
                    log.info("searchCriteria is not null -- calling tblHostsJpaController.findHostsByNameSearchCriteria(searchCriteria)");
                    tblHostList = tblHostsJpaController.findHostsByNameSearchCriteria(searchCriteria);
                    log.info(new Integer(tblHostList.size()).toString());
                } else {
                    log.info("calling tblHostsJpaController.findTblHostsEntities()");
                    tblHostList = tblHostsJpaController.findTblHostsEntities();
                    log.info(new Integer(tblHostList.size()).toString());
                }

//			if (tblHostList != null) {
                log.info(String.format("Found [%d] host results for search criteria [%s]", tblHostList.size(), searchCriteria));

                for (TblHosts tblHosts : tblHostList) {
                    TxtHostRecord hostObj = createTxtHostFromDatabaseRecord(tblHosts);
                    txtHostList.add(hostObj);
                }
//			} else {
//				log.info(String.format("Found no hosts for search criteria [%s]",searchCriteria));
//			}

                return txtHostList;
            } catch (ASException e) {
                throw e;
            } catch (CryptographyException e) {
                throw new ASException(e, ErrorCode.AS_ENCRYPTION_ERROR, e.getCause() == null ? e.getMessage() : e.getCause().getMessage());
            } catch (Exception e) {
                throw new ASException(e);
            }

	}
        
        /**
         * Author: Sudhir
         *
         * Searches for the hosts using the criteria specified.
         *
         * @param searchCriteria: If in case the user has not provided any
         * search criteria, then all the hosts would be returned back to the
         * caller
         * @param includeHardwareUuid: if this is set to true, it causes the resulting 
         * TxtHostRecord to include the hardware_uuid field from the tblHost
         * @return
         */
        public List<TxtHostRecord> queryForHosts(String searchCriteria,boolean includeHardwareUuid) {
                log.debug("queryForHost " + searchCriteria + " includeHardwareUuid[" + includeHardwareUuid +"]");
                try {
                        //TblHostsJpaController tblHostsJpaController = My.jpa().mwHosts(); //new TblHostsJpaController(getEntityManagerFactory());
                        TblHostsJpaController tblHostsJpaController = new TblHostsJpaController(getEntityManagerFactory());
                      
                        List<TxtHostRecord> txtHostList = new ArrayList<TxtHostRecord>();
                        List<TblHosts> tblHostList;


                        if (searchCriteria != null && !searchCriteria.isEmpty()) {
                                tblHostList = tblHostsJpaController.findHostsByNameSearchCriteria(searchCriteria);
                        } else {
                                tblHostList = tblHostsJpaController.findTblHostsEntities();
                        }

                        if (tblHostList != null) {

                                log.debug(String.format("Found [%d] host results for search criteria [%s]", tblHostList.size(), searchCriteria));

                                for (TblHosts tblHosts : tblHostList) {
                                        TxtHostRecord hostObj = createTxtHostFromDatabaseRecord(tblHosts,includeHardwareUuid);
                                        txtHostList.add(hostObj);
                                }
                        } else {
                                log.debug(String.format("Found no hosts for search criteria [%s]", searchCriteria));
                        }

                        return txtHostList;
                } catch (ASException e) {
                        throw e;
                } catch (Exception e) {
                        // throw new ASException(e);
                        // Bug: 1038 - prevent leaks in error messages to client
                        log.error("Error during querying for registered hosts.", e);
                        throw new ASException(ErrorCode.AS_QUERY_HOST_ERROR, e.getClass().getSimpleName());
                }

        }

	public TxtHostRecord createTxtHostFromDatabaseRecord(TblHosts tblHost) {
		TxtHostRecord hostObj = new TxtHostRecord();
		hostObj.HostName = tblHost.getName();
		hostObj.IPAddress = tblHost.getIPAddress();
		hostObj.Port = tblHost.getPort();
		hostObj.AddOn_Connection_String = tblHost.getAddOnConnectionInfo();
		hostObj.Description = tblHost.getDescription();
		hostObj.Email = tblHost.getEmail();
		hostObj.Location = tblHost.getLocation();
		hostObj.BIOS_Name = tblHost.getBiosMleId().getName();
		hostObj.BIOS_Oem = tblHost.getBiosMleId().getOemId().getName();
		hostObj.BIOS_Version = tblHost.getBiosMleId().getVersion();
		hostObj.VMM_Name = tblHost.getVmmMleId().getName();
		hostObj.VMM_Version = tblHost.getVmmMleId().getVersion();
		hostObj.VMM_OSName = tblHost.getVmmMleId().getOsId().getName();
		hostObj.VMM_OSVersion = tblHost.getVmmMleId().getOsId().getVersion();
                hostObj.Hardware_Uuid = tblHost.getHardwareUuid();

		return hostObj;
	}
	
	public TxtHostRecord createTxtHostFromDatabaseRecord(TblHosts tblHost,boolean includeHardwareUuid) {
                TxtHostRecord hostObj = new TxtHostRecord();
                hostObj.HostName = tblHost.getName();
                hostObj.IPAddress = tblHost.getName();
                hostObj.Port = tblHost.getPort();
                hostObj.AddOn_Connection_String = tblHost.getAddOnConnectionInfo();
                hostObj.Description = tblHost.getDescription();
                hostObj.Email = tblHost.getEmail();
                hostObj.Location = tblHost.getLocation();
                hostObj.BIOS_Name = tblHost.getBiosMleId().getName();
                hostObj.BIOS_Oem = tblHost.getBiosMleId().getOemId().getName();
                hostObj.BIOS_Version = tblHost.getBiosMleId().getVersion();
                hostObj.VMM_Name = tblHost.getVmmMleId().getName();
                hostObj.VMM_Version = tblHost.getVmmMleId().getVersion();
                hostObj.VMM_OSName = tblHost.getVmmMleId().getOsId().getName();
                hostObj.VMM_OSVersion = tblHost.getVmmMleId().getOsId().getVersion();
                if(includeHardwareUuid){
                    hostObj.Hardware_Uuid = tblHost.getHardwareUuid();
                }else{
                    hostObj.Hardware_Uuid = null;
                }
                
                /*
                // if the host already has a mtwilson 1.x tls keystore, automatically convert it to the new tls policy descriptor
                if( tblHost.getTlsPolicyName() != null || tblHost.getTlsKeystore() != null ) {
                    TblHostsTlsPolicyFactory.TblHostsObjectTlsPolicy tlsPolicyFactory = new TblHostsTlsPolicyFactory.TblHostsObjectTlsPolicy(tblHost);
                    hostObj.tlsPolicyChoice = tlsPolicyFactory.getTlsPolicyChoice();
                }
                else if( tblHost.getTlsPolicyId() != null ) {
                    // there is a policy id, but for the UI edit host page we need to provide the id for a shared policy, or the descriptor for a private policy
                    try(TlsPolicyDAO tlsPolicyDao = TlsPolicyJdbiFactory.tlsPolicyDAO()) {
                        TlsPolicyRecord tlsPolicyRecord = tlsPolicyDao.findPrivateTlsPolicyByHostId(tblHost.getUuid_hex());
                        if( tlsPolicyRecord != null && tblHost.getTlsPolicyId().equalsIgnoreCase(tlsPolicyRecord.getId().toString()) ) {
                            // found the private policy for this host, so set the descriptor on the host record
                            JsonTlsPolicyReader reader = new JsonTlsPolicyReader();
                            hostObj.tlsPolicyChoice = new TlsPolicyChoice();
                            hostObj.tlsPolicyChoice.setTlsPolicyDescriptor(reader.read(tlsPolicyRecord.getContent()));
                        }
                        else {
                            // either didn't find a private policy OR we found one but the host actually links to a shared policy - so keep the tls policy id
                            hostObj.tlsPolicyChoice = new TlsPolicyChoice();
                            hostObj.tlsPolicyChoice.setTlsPolicyId(tblHost.getTlsPolicyId());
                        }
                    }
                    catch(IOException e) {
                        log.debug("Cannot lookup tlsPolicyId {}", tblHost.getTlsPolicyId(), e);
                    }
                }
                else if( tblHost.getTlsPolicyDescriptor() != null ) {
                    hostObj.tlsPolicyChoice = new TlsPolicyChoice();
                    hostObj.tlsPolicyChoice.setTlsPolicyDescriptor(tblHost.getTlsPolicyDescriptor());
                } */
                
                return hostObj;
        }
        
        

	public TblHostsJpaController getHostsJpaController () throws CryptographyException {
		return new TblHostsJpaController(getEntityManagerFactory());
	}

	public TblMleJpaController getMleJpaController() {
		return new TblMleJpaController(getEntityManagerFactory());
	}
        
        public TblModuleManifestJpaController getModuleJpaController() {
                return new TblModuleManifestJpaController(getEntityManagerFactory());
        }
        
        public TblHostSpecificManifestJpaController getHostSpecificManifestJpaController() {
                return new TblHostSpecificManifestJpaController(getEntityManagerFactory());
        }
        
        public TblEventTypeJpaController getEventJpaController() {
            return new TblEventTypeJpaController(getEntityManagerFactory());
        }
        
        public TblPackageNamespaceJpaController getPackageJpaController() {
            return new TblPackageNamespaceJpaController(getEntityManagerFactory());
        }
        	
	public HostAgent getHostAgent(TblHosts tblHosts) {
		return new HostAgentFactory().getHostAgent(tblHosts);
	}
	
	public HostAgentFactory getHostAgentFactory() {
		return new HostAgentFactory();
	}
	
	public TblTaLogJpaController getTaLogJpaController() {
		return new TblTaLogJpaController(getEntityManagerFactory());
	}
        
        public TblSamlAssertionJpaController getSamlAssertionJpaController() {
		return new TblSamlAssertionJpaController(getEntityManagerFactory());
	}
        
        
}

