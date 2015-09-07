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
import com.intel.mtwilson.as.controller.TblHostsJpaController;
import com.intel.mtwilson.as.controller.TblLocationPcrJpaController;
import com.intel.mtwilson.as.controller.TblMleJpaController;
import com.intel.mtwilson.as.controller.TblPcrManifestJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.controller.exceptions.IllegalOrphanException;
import com.intel.mtwilson.as.controller.exceptions.NonexistentEntityException;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.as.helper.BaseBO;
import com.intel.mtwilson.crypto.CryptographyException;
//import com.intel.mtwilson.crypto.X509Util;
import com.intel.mtwilson.util.x509.X509Util;
import com.intel.mtwilson.datatypes.*;
import com.intel.mtwilson.util.ResourceFinder;

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

import org.apache.commons.io.IOUtils;
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
        private Logger log = LoggerFactory.getLogger(getClass());
	private TblMle biosMleId = null;
	private TblMle vmmMleId = null;
        
	public String addHost(TxtHost host) {
		String certificate = null;
		String location = null;
		String ipAddress = null;
		HashMap<String, ? extends IManifest> pcrMap = null;
		log.debug("About the add the host to the DB");
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
			log.debug("stdalex addHost cs == " + host.getAddOn_Connection_String());
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

			if (canFetchAIKCertificateForHost(host.getVmm().getName())) { // datatype.Vmm
				if (!host.getAddOn_Connection_String().toLowerCase()
						.contains("citrix")) {
					certificate = getAIKCertificateForHost(tblHosts, host);
					// we have to check that the aik certificate was signed by a trusted privacy ca
					X509Certificate hostAikCert = X509Util
							.decodePemCertificate(certificate);
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
			log.info(
					"Saving Host in database with TlsPolicyName {} and TlsKeystoreLength {}",
					tblHosts.getTlsPolicyName(),tblHosts.getTlsKeystore() == null ? "null" : tblHosts.getTlsKeystore().length);
                        Map<String,String> attributes = agent.getHostAttributes();
                        String hostUuidAttr;
                        if(attributes != null)
                             hostUuidAttr= attributes.get("Host_UUID");
                        if ((attributes != null) && (!attributes.isEmpty()) && (hostUuidAttr != null))
                            tblHosts.setHardwareUuid(hostUuidAttr.toLowerCase().trim());
//                        
			log.debug("Saving the host details in the DB");
			saveHostInDatabase(tblHosts, host, certificate, location, pcrMap);

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

			log.info("Saving Host in database");
			tblHosts.setBiosMleId(biosMleId);
			tblHosts.setDescription(host.getDescription());
			tblHosts.setEmail(host.getEmail());
			if (host.getIPAddress() != null)
				tblHosts.setIPAddress(host.getIPAddress().toString()); // datatype.IPAddress
			tblHosts.setPort(host.getPort());
			tblHosts.setVmmMleId(vmmMleId);

			log.info("Updating Host in database");
			getHostsJpaController().edit(tblHosts);

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
			deleteTALogs(tblHosts.getId());

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

	private void saveHostInDatabase(TblHosts newRecordWithTlsPolicyAndKeystore,TxtHost host, String certificate, String location,
			HashMap<String, ? extends IManifest> pcrMap) throws CryptographyException {

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

		// create the host
		log.debug("COMMITING NEW HOST DO DATABASE");
		hostController.create(tblHosts);

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
           TblHosts tblHosts = null;
           try {
              InetAddress addr = InetAddress.getByName(hostName.toString());
              String hostname = addr.getHostName();
              log.debug("hostname:" +hostname);
              String ip =  addr.getHostAddress();
              log.debug("ip:" +ip);
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
                                if (tblHostList != null)
                                    log.info(Integer.toString(tblHostList.size()));
                        }
                        else {
                                log.info("calling tblHostsJpaController.findTblHostsEntities()");
				tblHostList = tblHostsJpaController.findTblHostsEntities();
                                if (tblHostList != null)
                                    log.info(Integer.toString(tblHostList.size()));
                        }

			if (tblHostList != null) {

				log.info(String.format("Found [%d] host results for search criteria [%s]",tblHostList.size(), searchCriteria));

				for (TblHosts tblHosts : tblHostList) {
					TxtHostRecord hostObj = createTxtHostFromDatabaseRecord(tblHosts);
					txtHostList.add(hostObj);
				}
			} else {
				log.info(String.format("Found no hosts for search criteria [%s]",searchCriteria));
			}

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
                    //log.debug("adding in hardware uuid field["+tblHost.getHardwareUuid()+"]");
                    hostObj.Hardware_Uuid = tblHost.getHardwareUuid();
                }else{
                    log.debug("not adding in hardware uuid");
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
	
	public HostAgent getHostAgent(TblHosts tblHosts) {
		return new HostAgentFactory().getHostAgent(tblHosts);
	}
	
	public HostAgentFactory getHostAgentFactory() {
		return new HostAgentFactory();
	}
	
	public TblTaLogJpaController getTaLogJpaController() {
		return new TblTaLogJpaController(getEntityManagerFactory());
	}
}

