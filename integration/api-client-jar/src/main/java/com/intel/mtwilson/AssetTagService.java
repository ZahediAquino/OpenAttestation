/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.intel.mtwilson;

import com.intel.mtwilson.datatypes.AssetTagCertCreateRequest;
import com.intel.mtwilson.datatypes.AssetTagCertRevokeRequest;
import com.intel.mtwilson.datatypes.TxtHostRecord;
import java.io.IOException;
import java.security.SignatureException;
import java.util.List;

/**
 *
 * @author avaguayo
 */
public interface AssetTagService {
    
    /**
     * 
     * @param aTagObj
     * @return
     * @throws IOException
     * @throws ApiException
     * @throws SignatureException 
     */
    boolean importAssetTagCertificate(AssetTagCertCreateRequest aTagObj) throws IOException, ApiException, SignatureException;
    
      /**
     * Retrieves the list of hosts matching search criteria. Currently only search on the name is
     * supported. Empty search criteria retrieves all the hosts configured in the system.
     * <p>
     * <i><u>Roles needed:</u></i>Attestation/Report/Security
     * <p>
     * <i><u>Output content type:</u></i>Application/JSON
     * <p>
     * <i><u>Sample REST API call :</u></i><br>
     * <i>Method Type: GET</i><br>
     * https://192.168.1.101:8181/AttestationService/resources/hosts?searchCriteria=201&includeHardwareUuid=true<br>
     * <p>
     * <i><u>Sample Output:</u></i><br>
     *[{"HostName":"192.168.1.201","IPAddress":"192.168.1.201","Port":9999,"BIOS_Name":"Intel_Corp.","BIOS_Version":"T060","BIOS_Oem":"Intel Corp.","VMM_Name":"Intel_Thurley_Xen","VMM_Version":"11-4.1.0","VMM_OSName":"SUSE_LINUX","VMM_OSVersion":"11","AddOn_Connection_String":"intel:https://192.168.1.201:9999","Description":null,"Email":null,"Location":null,"AIK_Certificate":null,"AIK_PublicKey":null,"AIK_SHA1":null,"Processor_Info":null}]
     * <p>
     * <i><u>Sample Java API Call:</u></i><br>
     * List<TxtHostRecord> queryForHosts = apiClientObj.queryForHosts("201");
     * <p>
     * @param searchCriteria search criteria specified by the user. Search criteria applies just for the host name.
     * @parma includeHardwareUuid if set to true, api will include hardware_uuid field in txtHostRecord response, this will break backwards 1.2 compatabiltiy
     * @return List of {@link TxtHostRecord} objects matching the search criteria.
     * @throws IOException
     * @throws ApiException If there are any errors during the execution this exception would be returned to the caller.
     * The caller can use the getErrorCode() and getMessage() functions to retrieve the exception details.
     * @throws SignatureException 
     * @since MTW 1.0 Enterprise/1.2 Opensource
     */
    List<TxtHostRecord> queryForHosts(String searchCriteria,boolean includeHardwareUuid) throws IOException, ApiException, SignatureException;
    
    /**
     * 
     * @param aTagObj
     * @return
     * @throws IOException
     * @throws ApiException
     * @throws SignatureException 
     */
    boolean revokeAssetTagCertificate(AssetTagCertRevokeRequest aTagObj) throws IOException, ApiException, SignatureException;
    
}
