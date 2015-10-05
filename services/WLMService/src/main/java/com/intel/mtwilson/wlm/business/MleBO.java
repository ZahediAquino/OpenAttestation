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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.wlm.business;

import com.intel.mtwilson.as.controller.TblOsJpaController;
import com.intel.mtwilson.as.controller.TblOemJpaController;
import com.intel.mtwilson.as.controller.TblPcrManifestJpaController;
import com.intel.mtwilson.as.controller.TblMleJpaController;
//import com.intel.mtwilson.as.controller.TblDbPortalUserJpaController;
import com.intel.mtwilson.as.data.TblPcrManifest;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblOs;
import com.intel.mtwilson.as.data.TblOem;
import com.intel.mtwilson.as.data.TblMle;
//import com.intel.mtwilson.as.data.TblDbPortalUser;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.controller.MwMleSourceJpaController;
import com.intel.mtwilson.wlm.helper.BaseBO;
import com.intel.mtwilson.as.controller.exceptions.ASDataException;
import com.intel.mtwilson.as.controller.exceptions.IllegalOrphanException;
import com.intel.mtwilson.as.controller.exceptions.NonexistentEntityException;
import com.intel.mtwilson.as.data.MwMleSource;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.datatypes.ManifestData;
import com.intel.mtwilson.datatypes.MleData;
import com.intel.mtwilson.datatypes.MleSource;
import com.intel.mtwilson.datatypes.PCRWhiteList;
import com.intel.mtwilson.util.io.UUID;
import java.util.*;
//import java.util.logging.Level;
//import java.util.logging.Logger;
import javax.persistence.NoResultException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author dsmagadx
 */
public class MleBO extends BaseBO {

    Logger log = LoggerFactory.getLogger(getClass().getName());
    TblMleJpaController mleJpaController = null;
    TblPcrManifestJpaController pcrManifestJpaController = null;

    public MleBO() {
        mleJpaController = new TblMleJpaController(getEntityManagerFactory());
        pcrManifestJpaController = new TblPcrManifestJpaController(getEntityManagerFactory());
	}

	/**
	 * For VMM, the OS Name and OS Version in the new MLE must ALREADY be in the
	 * database, or this method will throw an error.
	 * 
	 * @param mleData
	 * @return
	 */
     public String addMLe(MleData mleData, String mleUuid) {
         String osOemUuid = null;
    	 try {
             TblMle tblMle = getMleDetails(mleData.getName(),
                             mleData.getVersion(), mleData.getOsName(),
                             mleData.getOsVersion(), mleData.getOemName());

             if (tblMle != null) {
                     throw new ASException(ErrorCode.WS_MLE_ALREADY_EXISTS, mleData.getName());
             }

             if(mleData.getName().toUpperCase().contains("ESX")){
                     String version = getUpperCase(mleData.getVersion()).substring(0, 2);
                     if(!version.equals("51") && !version.equals("50")){
                             throw new ASException(ErrorCode.WS_ESX_MLE_NOT_SUPPORTED);
                     }
             }
             if (mleData.getMleType().equals("VMM")) {
                TblOs osObj = new TblOsJpaController(getEntityManagerFactory())
				.findTblOsByNameVersion(mleData.getOsName(), mleData.getOsVersion());
                //TblOs osObj = My.jpa().mwOs().findTblOsByNameVersion(mleData.getOsName(), mleData.getOsVersion());
                osOemUuid = osObj.getUuid_hex();
            } else if (mleData.getMleType().equals("BIOS")) {
                TblOem oemObj = new TblOemJpaController(getEntityManagerFactory())
				.findTblOemByName(mleData.getOemName());
                //TblOem oemObj = My.jpa().mwOem().findTblOemByName(mleData.getOemName());
                osOemUuid = oemObj.getUuid_hex();
            }
             /*
             if (mleData.getMleType().equalsIgnoreCase("BIOS")){
                 if (mleData.getManifestList() != null){
                     for (ManifestData manifestData : mleData.getManifestList()) {
                         if (Integer.valueOf(manifestData.getName()).intValue() > 5 || Integer.valueOf(manifestData.getName()).intValue() < 0) {
                             throw new ASException(ErrorCode.WS_MLE_PCR_NOT_VALID, manifestData.getName());
                         }
                     }
                 }
             }
             
             if (mleData.getMleType().equalsIgnoreCase("VMM")){
                 if (mleData.getManifestList() != null){
                     for (ManifestData manifestData : mleData.getManifestList()) {
                         if (Integer.valueOf(manifestData.getName()).intValue() > 20 || Integer.valueOf(manifestData.getName()).intValue() < 17) {
                             throw new ASException(ErrorCode.WS_MLE_PCR_NOT_VALID, manifestData.getName());
                         }
                     }
                 }
             }*/
             tblMle = getTblMle(mleData, mleUuid, osOemUuid);
             mleJpaController.create(tblMle);
             addPcrManifest(tblMle, mleData.getManifestList());
     } catch (ASException ase) {
         throw ase;
     } catch (Exception e) {

         throw new ASException(e);
     }
     return "true";
                                
	}
	
    /**
     * 
     * @param str
     * @return 
     */
     private String getUpperCase(String str) {
         if(str != null){
             return str.toUpperCase().replaceAll("[/.]","");
         }
         return "NULL";
     }
             
   /**
    * 
    * @param mleData
    * @return 
    */
    public String updateMle(MleData mleData) {
		try {
            TblMle tblMle = getMleDetails(mleData.getName(),
                            mleData.getVersion(), mleData.getOsName(),
                            mleData.getOsVersion(), mleData.getOemName());

            if (tblMle == null && mleData.getOemName() != null) {
                    throw new ASException(ErrorCode.WS_MLE_OEM_DOES_NOT_EXIST, 
                    		mleData.getName(), mleData.getVersion(), mleData.getOemName());
            }
            if (tblMle == null && mleData.getOsName() != null) {
                throw new ASException(ErrorCode.WS_MLE_OS_DOES_NOT_EXIST, 
                		mleData.getName(), mleData.getVersion(), mleData.getOsName(), mleData.getOsVersion());
            }

            setTblMle(tblMle, mleData);

            mleJpaController.edit(tblMle);
            updatePcrManifest(tblMle, mleData);

            } catch (ASException ase) {
            	throw ase;
            } catch (Exception e) {
            	new ASException(e);
            }
		return "true";
            
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
    public String deleteMle(String mleName, String mleVersion, String osName, String osVersion, String oemName) {
    	try {
            TblMle tblMle = getMleDetails(mleName, mleVersion, osName, osVersion, oemName);

            if (tblMle == null) {
                    throw new ASException(ErrorCode.WS_MLE_DOES_NOT_EXIST, mleName, mleVersion);
            }

            Collection<TblHosts> tblHostsCollection;
            if (oemName == null || oemName.isEmpty()) {
                tblHostsCollection = tblMle.getTblHostsCollection();
            } else {
                tblHostsCollection = tblMle.getTblHostsCollection1();
            }
            if( tblHostsCollection != null ) {
                log.info(String.format("MLE '%s' is currently associated with '%d' hosts. ", mleName, tblHostsCollection.size()));

                if (!tblHostsCollection.isEmpty()) {
                    throw new ASException(ErrorCode.WS_MLE_ASSOCIATION_EXISTS, mleName, mleVersion, tblHostsCollection.size());
                }
            }

            for (TblPcrManifest manifest : tblMle.getTblPcrManifestCollection()) {
                    pcrManifestJpaController.destroy(manifest.getId());
            }

            // We also need to delete entries in the MleSource table for the MLE. This table would store the host
            // name that was used to white list the MLE.
            deleteMleSource(mleName, mleVersion, osName, osVersion, oemName);

            mleJpaController.destroy(tblMle.getId());

        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }

        return "true";
    }

   /**
    * 
    * @param searchCriteria
    * @return 
    */
	public List<MleData> listMles(String searchCriteria) {
		List<MleData> mleDataList = new ArrayList<MleData>();

        List<TblMle> tblMleList;

        try {
            if (searchCriteria != null && !searchCriteria.isEmpty())
                    tblMleList = mleJpaController .findMleByNameSearchCriteria(searchCriteria);
            else
                    tblMleList = mleJpaController.findTblMleEntities();

            if (tblMleList != null) {
                    log.info(String.format("Found [%d] mle results for search criteria [%s]", tblMleList.size(), searchCriteria));

                    for (TblMle tblMle : tblMleList) {
                            MleData mleData = createMleDataFromDatabaseRecord(tblMle, false);
                            mleDataList.add(mleData);
                    }
            } else {
                    log.info(String.format("Found [%d] mle results for search criteria [%s]", 0,searchCriteria));
            }

        } catch (ASException ase) {
                throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }
        return mleDataList;
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
    public MleData findMle(String mleName, String mleVersion, String osName, String osVersion, String oemName) {
    	try {
            TblMle tblMle = getMleDetails(mleName, mleVersion, osName, osVersion, oemName);

            if (tblMle == null) {
                throw new ASException(ErrorCode.WS_MLE_DOES_NOT_EXIST, mleName, mleVersion);                        
            }

            MleData mleData = createMleDataFromDatabaseRecord(tblMle, true);
            return mleData;

        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
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
	private TblMle getMleDetails(String mleName, String mleVersion,	String osName, String osVersion, String oemName) {
		TblMle tblMle;
        log.info(String.format("Mle name '%s' version '%s' os '%s' os version '%s' oem '%s'. ",
                        mleName, mleVersion, osName, osVersion, oemName));
        validateNull("mleName", mleName);
        validateNull("mleVersion", mleVersion);
        validateMleExtraAttributes(osName, osVersion, oemName);
        if (StringUtils.isNotBlank(oemName)) {
                log.info("Getting BIOS MLE from database");
                tblMle = mleJpaController.findBiosMle(mleName, mleVersion, oemName);
        } else {
                log.info("Get VMM MLE from database");
                tblMle = mleJpaController.findVmmMle(mleName, mleVersion, osName,osVersion);
        }
        return tblMle;
	}

        /**
         * 
         * @param tblMle
         * @param addManifest
         * @return 
         */
	public MleData createMleDataFromDatabaseRecord(TblMle tblMle, boolean addManifest) {
		List<ManifestData> manifestList = null;

        if (addManifest) {
                manifestList = new ArrayList<ManifestData>();
                for (TblPcrManifest pcrManifest : tblMle.getTblPcrManifestCollection()) {
                        manifestList.add(new ManifestData(pcrManifest.getName(), pcrManifest.getValue()));
                }
        }

        String osName = (tblMle.getOsId() == null) ? null : tblMle.getOsId().getName();
        String osVersion = (tblMle.getOsId() == null) ? null : tblMle.getOsId().getVersion();
        String oemName = (tblMle.getOemId() == null) ? null : tblMle.getOemId().getName();

        MleData s = new MleData(tblMle.getName(), tblMle.getVersion(), MleData.MleType.valueOf(tblMle.getMLEType()),
                        MleData.AttestationType.valueOf(tblMle.getAttestationType()),
                        manifestList, tblMle.getDescription(), osName, osVersion, oemName);

        return s;
                                
	}

        /**
         * 
         * @param mleData
         * @return 
         */
	private TblMle getTblMle(MleData mleData, String mleUuid, String osOemUuid) {
		TblMle tblMle = new TblMle();

		tblMle.setMLEType(mleData.getMleType());
		tblMle.setName(mleData.getName());
		tblMle.setVersion(mleData.getVersion());
		tblMle.setAttestationType(mleData.getAttestationType());
		tblMle.setDescription(mleData.getDescription());
		tblMle.setRequiredManifestList(getRequiredManifestList(mleData
                .getManifestList()));
                if (mleUuid != null && !mleUuid.isEmpty()) {
                    tblMle.setUuid_hex(mleUuid);
                } else {
                    tblMle.setUuid_hex(new UUID().toString());
                }

		if (mleData.getMleType().equals("VMM")) {
			tblMle.setOsId(getTblOs(mleData.getOsName(), mleData.getOsVersion()));
                        tblMle.setOs_uuid_hex(osOemUuid);
		} else if (mleData.getMleType().equals("BIOS")) {
			tblMle.setOemId(getTblOem(mleData.getOemName()));
                        tblMle.setOem_uuid_hex(osOemUuid);
		}

		return tblMle;
	}

        /**
         * 
         * @param mleManifests
         * @return 
         */
	private List<String> manifestNames(List<ManifestData> mleManifests) {
		ArrayList<String> names = new ArrayList<String>();
		for( ManifestData manifestData : mleManifests ) {
			names.add( manifestData.getName().trim() );
		}
		return names;
	}
        
        /**
         * 
         * @param mleManifests
         * @return 
         */
	private String getRequiredManifestList(List<ManifestData> mleManifests) {
		String manifestList = mleManifests == null ? "" : StringUtils.join(manifestNames(mleManifests), ",");
		log.info("Required Manifest list: " + manifestList);
		return manifestList;
	}

        /**
         * 
         * @param label
         * @param input
         * @return 
         */
	private String validateNull(String label, String input) {
		if (input == null || input.isEmpty()) {
			log.info(String.format("Required input parameter '%s' is null or missing.", label));
			throw new ASException(ErrorCode.WS_MLE_DATA_MISSING, label);
		}
		return input;
	}

	private void addPcrManifest(TblMle tblMle, List<ManifestData> mleManifests) throws IllegalOrphanException, NonexistentEntityException, ASDataException {
		
		Collection<TblPcrManifest> tblPcrManifests = new ArrayList<TblPcrManifest>();

		if (mleManifests != null) {

			for (ManifestData manifestData : mleManifests) {
				TblPcrManifest pcrManifest = new TblPcrManifest();
				pcrManifest.setName(manifestData.getName());
				pcrManifest.setValue(manifestData.getValue());
				pcrManifest.setMleId(tblMle);
				pcrManifestJpaController.create(pcrManifest);
				tblPcrManifests.add(pcrManifest);
			}
		}
		
		tblPcrManifests.addAll(tblMle.getTblPcrManifestCollection());
		tblMle.setTblPcrManifestCollection(tblPcrManifests);
		String oldRequiredManifestList = tblMle.getRequiredManifestList() ==null || tblMle.getRequiredManifestList().length() == 0 ? "":tblMle.getRequiredManifestList()+",";
		tblMle.setRequiredManifestList(oldRequiredManifestList +getRequiredManifestList(mleManifests));
		mleJpaController.edit(tblMle);

	}

        /**
         * 
         */
	private void setTblMle(TblMle tblMle, MleData mleData) {
		// tblMle.setMLEType(mleData.getMleType().toString());
		// tblMle.setAttestationType(mleData.getAttestationType().toString());
		tblMle.setDescription(mleData.getDescription());
		tblMle.setRequiredManifestList(getRequiredManifestList(mleData
				.getManifestList()));
	}

        /**
         * 
         * @param tblMle
         * @param mleData
         * @throws NonexistentEntityException
         * @throws ASDataException 
         */
	private void updatePcrManifest(TblMle tblMle, MleData mleData) throws NonexistentEntityException, ASDataException {
		HashMap<String, String> newPCRMap = getPcrMap(mleData);

		if (tblMle.getTblPcrManifestCollection() != null) { // this can be null for MODULE Manifest

			for (TblPcrManifest pcrManifest : tblMle.getTblPcrManifestCollection()) {
				if (newPCRMap.containsKey(pcrManifest.getName())) {
					log.info(String.format("Updating Pcr manifest value for mle %s  version %s pcr name %s",
                                                pcrManifest.getMleId().getName(), pcrManifest.getMleId().getVersion(),
						pcrManifest.getName()));
					pcrManifest.setValue(newPCRMap.get(pcrManifest.getName()));
					pcrManifestJpaController.edit(pcrManifest);
					newPCRMap.remove(pcrManifest.getName());
				} else {
					log.info(String.format("Deleting Pcr manifest value for mle %s  version %s pcr name %s",
						pcrManifest.getMleId().getName(), pcrManifest.getMleId().getVersion(),
						pcrManifest.getName()));
					pcrManifestJpaController.destroy(pcrManifest.getId());
				}
			}
                        
			for (String pcrName : newPCRMap.keySet()) {

				TblPcrManifest pcrManifest = new TblPcrManifest();
				pcrManifest.setName(pcrName);
				pcrManifest.setValue(newPCRMap.get(pcrName));
				pcrManifest.setMleId(tblMle);

				log.info(String.format("Creating Pcr manifest value for mle %s  version %s pcr name %s",
					pcrManifest.getMleId().getName(), pcrManifest.getMleId().getVersion(), 
                                        pcrManifest.getName()));

				pcrManifestJpaController.create(pcrManifest);
			}
		}

	}

        /**
         * 
         * @param mleData
         * @return 
         */
	private HashMap<String, String> getPcrMap(MleData mleData) {
		HashMap<String, String> pcrMap = new HashMap<String, String>();

		if (mleData.getManifestList() != null) {
			for (ManifestData manifestData : mleData.getManifestList()) {
				pcrMap.put(manifestData.getName(), manifestData.getValue());
			}
		}

		return pcrMap;
	}

        /**
         * 
         * @param osName
         * @param osVersion
         * @return 
         */
	private TblOs getTblOs(String osName, String osVersion) {
		TblOs tblOs = new TblOsJpaController(getEntityManagerFactory())
				.findTblOsByNameVersion(osName, osVersion);

		if (tblOs == null)
			throw new ASException(ErrorCode.WS_OS_DOES_NOT_EXIST, osName, osVersion);

		return tblOs;
	}

        /**
         * 
         * @param oemName
         * @return 
         */
	private TblOem getTblOem(String oemName) {
		TblOem tblOem = new TblOemJpaController(getEntityManagerFactory())
				.findTblOemByName(oemName);

		if (tblOem == null)
			throw new ASException(ErrorCode.WS_OEM_DOES_NOT_EXIST, oemName);

		return tblOem;
	}

        /**
         * 
         * @param osName
         * @param osVersion
         * @param oemName 
         */
	private void validateMleExtraAttributes(String osName, String osVersion, String oemName) {
		if (StringUtils.isNotBlank(oemName)) {
			if ((StringUtils.isNotBlank(osName) || StringUtils.isNotBlank(osVersion)))
				throw new ASException(ErrorCode.WS_OEM_OS_DATA_CANNOT_COEXIST);
		} else if (StringUtils.isBlank(osName) || StringUtils.isBlank(osVersion)) {
			throw new ASException(ErrorCode.WS_MLE_DATA_MISSING, "OEM/OS");
		}

	}

        
        /**
         * Added By: Sudhir on June 20, 2012
         * 
         * Processes the add request for a new PCR white list for the specified MLE.
         * 
         * @param pcrData: White list data sent by the user
         * @return : true if the call is successful or else exception.
         */
	public String addPCRWhiteList(PCRWhiteList pcrData) {
		TblMle tblMle;
        TblPcrManifest tblPcr;
        try {
        	tblMle = getMleDetails(pcrData.getMleName(),
                    pcrData.getMleVersion(), pcrData.getOsName(),
                    pcrData.getOsVersion(), pcrData.getOemName());
        	if (tblMle == null && pcrData.getOemName() != null) {
                throw new ASException(ErrorCode.WS_MLE_OEM_DOES_NOT_EXIST, pcrData.getMleName(), pcrData.getMleVersion(), pcrData.getOemName());
            }
            if (tblMle == null && pcrData.getOsName() != null) {
                throw new ASException(ErrorCode.WS_MLE_OS_DOES_NOT_EXIST, pcrData.getMleName(), pcrData.getMleVersion(), pcrData.getOsName(),pcrData.getOsVersion());
            }
           // Now we need to check if PCR is already configured. If yes, then
           // we ned to ask the user to use the Update option instead of create
           tblPcr = getPCRWhiteListDetails(tblMle.getId(), pcrData.getPcrName());
           if (tblPcr != null) {
                throw new ASException(ErrorCode.WS_PCR_WHITELIST_ALREADY_EXISTS, pcrData.getPcrName());
           }

/*
           if (StringUtils.isNotBlank(pcrData.getOemName())) {
               log.info("BIOS MLE, check the range of PCR value " + pcrData.getPcrName());
               if (Integer.valueOf(pcrData.getPcrName()).intValue() > 5 || Integer.valueOf(pcrData.getPcrName()).intValue() < 0)
                   throw new ASException(ErrorCode.WS_MLE_PCR_NOT_VALID, pcrData.getPcrName());
           } else {
               log.info("VMM MLE, check the range of PCR value " + pcrData.getPcrName());
               if (Integer.valueOf(pcrData.getPcrName()).intValue() > 20 || Integer.valueOf(pcrData.getPcrName()).intValue() < 17)
                   throw new ASException(ErrorCode.WS_MLE_PCR_NOT_VALID, pcrData.getPcrName());
           } */
           
           // In order to reuse the addPCRManifest function, we need to create a list and
           // add a single entry into it using the manifest data that we got.
           List<ManifestData> pcrWhiteList = new ArrayList<ManifestData>();
           pcrWhiteList.add(new ManifestData(pcrData.getPcrName(), pcrData.getPcrDigest()));

           // Now add the pcr to the database.
           addPcrManifest(tblMle, pcrWhiteList);
        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }
        return "true";
	}
        
        
        /**
         * Added By: Sudhir on June 20, 2012
         * 
         * Retrieves the details of the PCR manifest entry if exists.
         * 
         * @param mle_id : Identity of the MLE
         * @param pcrName : Name of the PCR
         * @return : Data row containing the PCR manifest details.
         */
	private TblPcrManifest getPCRWhiteListDetails(Integer mle_id, String pcrName) {
                                TblPcrManifest tblPcr;
                                validateNull("pcrName", pcrName);
                                tblPcr = pcrManifestJpaController.findByMleIdName(mle_id, pcrName);
                                return tblPcr;
	}

        
        /**
         * Added By: Sudhir on June 20, 2012
         * 
         * Processes the update request for an existing PCR white list for the specified MLE.
         * 
         * @param pcrData: White list data sent by the user
         * @return : true if the call is successful or else exception.
         */
	public String updatePCRWhiteList(PCRWhiteList pcrData) {
		TblMle tblMle;
        TblPcrManifest tblPcr; 

        try {
        	tblMle = getMleDetails(pcrData.getMleName(),
                    pcrData.getMleVersion(), pcrData.getOsName(),
                    pcrData.getOsVersion(), pcrData.getOemName());
        	if (tblMle == null && pcrData.getOemName() != null) {
                throw new ASException(ErrorCode.WS_MLE_OEM_DOES_NOT_EXIST, pcrData.getMleName(), pcrData.getMleVersion(), pcrData.getOemName());
            }
            if (tblMle == null && pcrData.getOsName() != null) {
                throw new ASException(ErrorCode.WS_MLE_OS_DOES_NOT_EXIST, pcrData.getMleName(), pcrData.getMleVersion(), pcrData.getOsName(),pcrData.getOsVersion());
            }

            // Now we need to check if PCR is already configured. If yes, then
            // we ned to ask the user to use the Update option instead of create
            tblPcr = getPCRWhiteListDetails(tblMle.getId(), pcrData.getPcrName());
            if (tblPcr == null) {
                 throw new ASException(ErrorCode.WS_PCR_WHITELIST_DOES_NOT_EXIST, pcrData.getPcrName());
            }
            // Now update the pcr in the database.
            tblPcr.setValue(pcrData.getPcrDigest());
            pcrManifestJpaController.edit(tblPcr);

        } catch (ASException ase) {
            throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }
        return "true";
	}
        
        
        /**
         * 
         * Added By: Sudhir on June 20, 2012
         * 
         * Processes the delete request for an existing PCR white list for the specified MLE.
         * 
         * @param pcrName : Name of the PCR, which is usually the number
         * @param mleName : Name of the associated MLE
         * @param mleVersion : Version of the associated MLE
         * @param osName : OS name associated with the VMM MLE
         * @param osVersion : OS version associated with the VMM MLE
         * @param oemName : OEM Name associated with the BIOS MLE
         * @return 
         */
	public String deletePCRWhiteList(String pcrName, String mleName, String mleVersion, String osName,
			String osVersion, String oemName) {
		TblPcrManifest tblPcr;
        TblMle tblMle;
        try {
        	tblMle = getMleDetails(mleName, mleVersion, osName, osVersion,oemName);
        	if (tblMle == null && oemName != null) {
                throw new ASException(ErrorCode.WS_MLE_OEM_DOES_NOT_EXIST, mleName, mleVersion, oemName);
            }
            if (tblMle == null && osName != null) {
                throw new ASException(ErrorCode.WS_MLE_OS_DOES_NOT_EXIST, mleName, mleVersion, osName, osVersion);
            }
            
            // Now we need to check if PCR value exists. If it does, then we do delete or else
            // we still return true since the data does not exist.
            tblPcr = getPCRWhiteListDetails(tblMle.getId(), pcrName);
            if (tblPcr == null) {
            	return "true";
            }

            // Delete the PCR white list entry.
            pcrManifestJpaController.destroy(tblPcr.getId());

        } catch (ASException ase) {
                throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }                
        return "true";
	}
        


   /**
    * Creates a new mapping entry in the DB between the MLE and the host that was used for whitelisiting.
    * 
    * @param mleSourceObj : Object containing the details of the host and the MLE.
    * @return True or False
    */
    public String addMleSource(MleSource mleSourceObj) {
    	TblMle tblMle;
        MleData mleData = null;
        try {

            try {
                mleData = mleSourceObj.getMleData();
                // Verify if the MLE exists in the system.
                tblMle = getMleDetails(mleData.getName(), mleData.getVersion(), mleData.getOsName(),
                                mleData.getOsVersion(), mleData.getOemName());
            } catch (NoResultException nre){
                throw new ASException(nre,ErrorCode.WS_MLE_DOES_NOT_EXIST, mleData.getName(), mleData.getVersion());
            }

            MwMleSourceJpaController mleSourceJpaController = new MwMleSourceJpaController(getEntityManagerFactory());

            // Let us check if there is a mapping entry already for this MLE. If it does, then we need to return
            // back appropriate error.
            MwMleSource mleSourceCurrentObj = mleSourceJpaController.findByMleId(tblMle.getId());

            if (mleSourceCurrentObj != null) {
                log.error("White List host is already mapped to the MLE - " + tblMle.getName());
                throw new ASException(ErrorCode.WS_MLE_SOURCE_MAPPING_ALREADY_EXISTS, mleData.getName());
            }

            // Else create a new entry in the DB.
            MwMleSource mleSourceData = new MwMleSource();
            mleSourceData.setMleId(tblMle);
            mleSourceData.setHostName(mleSourceObj.getHostName());        

            mleSourceJpaController.create(mleSourceData);

        } catch (ASException ase) {
                throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }                                
        return "true";
	}
        
        
   /**
    * Updates an existing MLE with the name of the white list host that was used to modify the white list values.
    * @param mleSourceObj
    * @return 
    */
    public String updateMleSource(MleSource mleSourceObj) {
    	TblMle tblMle;
        MleData mleData = null;
        try {

            try {
                mleData = mleSourceObj.getMleData();
                // Verify if the MLE exists in the system.
                tblMle = getMleDetails(mleData.getName(), mleData.getVersion(), mleData.getOsName(),
                                mleData.getOsVersion(), mleData.getOemName());
            } catch (NoResultException nre){
                throw new ASException(nre,ErrorCode.WS_MLE_DOES_NOT_EXIST, mleData.getName(), mleData.getVersion());
            }
                            
            MwMleSourceJpaController mleSourceJpaController = new MwMleSourceJpaController(getEntityManagerFactory());
            // If the mapping does not exist already in the db, then we need to return back error.
            MwMleSource mwMleSource = mleSourceJpaController.findByMleId(tblMle.getId());
            if (mwMleSource == null) {
                throw new ASException(ErrorCode.WS_MLE_SOURCE_MAPPING_DOES_NOT_EXIST, mleData.getName());
            }
            
            mwMleSource.setHostName(mleSourceObj.getHostName());        
            mleSourceJpaController.edit(mwMleSource);
            
            } catch (ASException ase) {
                throw ase;
            } catch (Exception e) {
                throw new ASException(e);
        }                                
        return "true";
    }

        
   /**
    * Deletes an existing mapping between the MLE and the WhiteList host that was used during the creation of MLE.
    * This method is called during the deletion of MLEs.
    * 
    * @param mleName
    * @param mleVersion
    * @param osName
    * @param osVersion
    * @param oemName
    * @return 
    */
    public String deleteMleSource(String mleName, String mleVersion, String osName, String osVersion, String oemName) {
    	TblMle tblMle;
        try {
            
            try {
                // First check if the entry exists in the MLE table.
                tblMle = getMleDetails(mleName, mleVersion, osName, osVersion, oemName);

            } catch (NoResultException nre){
                throw new ASException(nre,ErrorCode.WS_MLE_DOES_NOT_EXIST, mleName, mleVersion);
            }
                            
            MwMleSourceJpaController mleSourceJpaController = new MwMleSourceJpaController(getEntityManagerFactory());
            MwMleSource mwMleSource = mleSourceJpaController.findByMleId(tblMle.getId());
            // If the mapping does not exist, it is ok. We don't need to worry. Actually for MLES
            // configured manully, this entry does not exist.
            if  (mwMleSource != null)                                
                mleSourceJpaController.destroy(mwMleSource.getId());
            
        } catch (ASException ase) {
                throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }                                      
        return "true";
    }
            

        
   /**
    * Retrieves the host name that was used to white list the MLE specified.
    * 
    * @param mleName
    * @param mleVersion
    * @param osName
    * @param osVersion
    * @param oemName
    * @return 
    */
    public String getMleSource(String mleName, String mleVersion, String osName, String osVersion, String oemName) {
    	TblMle tblMle;
        String hostName = null;
        try {
            
            try {
                // First check if the entry exists in the MLE table.
                tblMle = getMleDetails(mleName, mleVersion, osName, osVersion, oemName);

            } catch (NoResultException nre){
                throw new ASException(nre,ErrorCode.WS_MLE_DOES_NOT_EXIST, mleName, mleVersion);
            }
                            
            MwMleSourceJpaController mleSourceJpaController = new MwMleSourceJpaController(getEntityManagerFactory());
            MwMleSource mwMleSource = mleSourceJpaController.findByMleId(tblMle.getId());
            
            // Now check if the data exists in the MLE Source table. If there is no corresponding entry, then we know that
            // the MLE was configured manually. 
            if (mwMleSource == null) {
                hostName = "Manually configured white list";
            }
            else {
                hostName = mwMleSource.getHostName();
            }
            
            return hostName;
            
        } catch (ASException ase) {
                throw ase;
        } catch (Exception e) {
            throw new ASException(e);
        }                                                
    }
}

