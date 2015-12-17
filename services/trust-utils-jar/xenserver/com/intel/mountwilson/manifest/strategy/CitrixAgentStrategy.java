/* */
package com.intel.mountwilson.manifest.strategy;

import java.util.HashMap;

import javax.persistence.EntityManagerFactory;

import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.controller.TblMleJpaController;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mountwilson.manifest.IManifestStrategy;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.helper.TAHelper;
import com.intel.mtwilson.agent.HostAgentFactory;
import com.intel.mtwilson.agent.citrix.CitrixClient;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.tls.TlsConnection;
import com.intel.mtwilson.tls.TlsPolicy;
/* */
/**
 * XXX needs to move to a trust-agent specific package
 */
/* */
public class CitrixAgentStrategy implements IManifestStrategy  {

    EntityManagerFactory entityManagerFactory;
 /* */ 
	/**
     *
     * @param entityManagerFactory
     */
/* */
    public CitrixAgentStrategy(EntityManagerFactory entityManagerFactory) {
		this.entityManagerFactory = entityManagerFactory;
	}

	public EntityManagerFactory getEntityManagerFactory() {
		return entityManagerFactory;
	}
	
	public void setEntityManagerFactory(EntityManagerFactory entityManagerFactory) {
		this.entityManagerFactory = entityManagerFactory;
	}
    
    @Override
    public HashMap<String, ? extends IManifest> getManifest(TblHosts host) throws Exception {
        String pcrList = getPcrList(host);
        HostAgentFactory factory = new HostAgentFactory();
        TlsPolicy tlsPolicy = factory.getTlsPolicy(host.getTlsPolicyName(), host.getTlsKeystoreResource());
        CitrixClient client = new CitrixClient(new TlsConnection(host.getAddOnConnectionInfo(), tlsPolicy));
        return client.getQuoteInformationForHost(pcrList);
    }
 
    private String getPcrList(TblHosts tblHosts) {
        // Get the Bios MLE without accessing cache    
        TblMle biosMle = new TblMleJpaController(getEntityManagerFactory()).findMleById(tblHosts.getBiosMleId().getId());
        String biosPcrList = biosMle.getRequiredManifestList();

        if (biosPcrList.isEmpty()) {
            throw new ASException(ErrorCode.AS_MISSING_MLE_REQD_MANIFEST_LIST, tblHosts.getBiosMleId().getName(), tblHosts.getBiosMleId().getVersion());
        }

        // Get the Vmm MLE without accessing cache
        TblMle vmmMle = new TblMleJpaController(getEntityManagerFactory()).findMleById(tblHosts.getVmmMleId().getId());

        String vmmPcrList = vmmMle.getRequiredManifestList();

        if (vmmPcrList == null || vmmPcrList.isEmpty()) {
            throw new ASException(ErrorCode.AS_MISSING_MLE_REQD_MANIFEST_LIST, tblHosts.getVmmMleId().getName(), tblHosts.getVmmMleId().getVersion());
        }

        return biosPcrList + "," + vmmPcrList;

    }
     
}
/* */
