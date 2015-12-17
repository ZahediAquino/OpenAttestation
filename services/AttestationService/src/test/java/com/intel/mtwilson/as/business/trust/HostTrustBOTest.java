package com.intel.mtwilson.as.business.trust;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import javax.persistence.EntityManagerFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.any;

import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.intel.mountwilson.manifest.IManifestStrategy;
import com.intel.mountwilson.manifest.IManifestStrategyFactory;
import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mtwilson.as.business.trust.gkv.IGKVStrategy;
import com.intel.mtwilson.as.controller.TblHostsJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblOem;
import com.intel.mtwilson.as.data.TblOs;
import com.intel.mtwilson.as.data.TblPcrManifest;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.datatypes.HostTrustStatus;
import com.intel.mtwilson.util.net.Hostname;
import com.intel.mtwilson.datatypes.OpenStackHostTrustLevelQuery;
import com.intel.mtwilson.datatypes.OpenStackHostTrustLevelReport;

@RunWith(MockitoJUnitRunner.class)
public class HostTrustBOTest {
	@Spy
	private HostTrustBO hostTrustBO = new HostTrustBO();
	
	@Mock
	IManifestStrategyFactory strategyFactory;
	
	@Mock
	private EntityManagerFactory emf;
	
	@Mock
	private IManifestStrategy manifestStrategy;
	
	@Mock
	private IGKVStrategy gkvStrategy;
	
	@Mock
	private TblTaLogJpaController taLogJpaController;
	
	private static final String SERVER_NAME = "127.0.0.1";
	
    @Before 
    public void setUp() throws Exception{
    	doReturn(emf).when(hostTrustBO).getEntityManagerFactory();
    	doReturn(taLogJpaController).when(hostTrustBO).getTblTaLogJpaController();
    	doReturn(strategyFactory).when(hostTrustBO).getManifestStrategyFactory();
    	doReturn(manifestStrategy).when(hostTrustBO).getManifestStrategy(any(TblHosts.class));
    	doReturn(gkvStrategy).when(hostTrustBO).getGkvStrategy(any(TblHosts.class));
    }
    
	@Test
	public void testGetTrustStatus() throws Exception {
		TblHosts tblHosts = mockGetHostByIpAddress();
		doReturn(tblHosts).when(hostTrustBO).getHostByIpAddress(SERVER_NAME);
		
		//get pcrMap 
		HashMap<String, IManifest> pcrManifestMap = new HashMap<String, IManifest>();
		pcrManifestMap.put("0", new PcrManifest(0, "31B97D97B4679917EC3C1D943635693FFBAB4143"));
		pcrManifestMap.put("18", new PcrManifest(18, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
		doReturn(pcrManifestMap).when(manifestStrategy).getManifest(tblHosts);
		
		//get gkv for given host
		HashMap<String, IManifest> gkvBiosPcrManifestMap = new HashMap<String, IManifest>();
		HashMap<String, IManifest> gkvVmmPcrManifestMap = new HashMap<String, IManifest>();
		gkvBiosPcrManifestMap.put("0", new PcrManifest(0, "31B97D97B4679917EC3C1D943635693FFBAB4143"));
		gkvVmmPcrManifestMap.put("18", new PcrManifest(18, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
		doReturn(gkvBiosPcrManifestMap).when(gkvStrategy).getBiosGoodKnownManifest(anyString(), anyString(), anyString());
		doReturn(gkvVmmPcrManifestMap).when(gkvStrategy).getVmmGoodKnownManifest(
				anyString(), anyString(), anyString(), anyString(), any(Integer.class));
		doNothing().when(taLogJpaController).create(any(TblTaLog.class));
		HostTrustStatus trustStatus = hostTrustBO.getTrustStatus(new Hostname(SERVER_NAME));
		assertNotNull(trustStatus);
		assertTrue(trustStatus.bios);
		assertTrue(trustStatus.vmm);
	}
	
	@Test
	public void testGetPollHosts() {
		OpenStackHostTrustLevelReport hostTrusts = null;
		OpenStackHostTrustLevelQuery input = new OpenStackHostTrustLevelQuery();
		String hostTrustStatus = "BIOS:1,VMM:1";
		String[] hosts = {SERVER_NAME};
		input.setHosts(hosts);
		doReturn(hostTrustStatus).when(hostTrustBO).getTrustStatusString(any(Hostname.class));
		hostTrusts = hostTrustBO.getPollHosts(input);
		assertNotNull(hostTrusts);
	}
	
	public TblHosts mockGetHostByIpAddress() {
		TblHosts tblHosts = new TblHosts();
		tblHosts.setId(1);
		tblHosts.setName(SERVER_NAME);
		tblHosts.setIPAddress(SERVER_NAME);
		
		String biosName = "DELL";
		String biosVersion = "A08";
		String oemName = "DELL";
	    TblMle biosMle = new TblMle();
	    biosMle.setId(1);
	    biosMle.setName(biosName);
	    biosMle.setVersion(biosVersion);
	    TblOem oem = new TblOem();
	    oem.setId(1);
	    oem.setName(oemName);
	    biosMle.setOemId(oem);
	    Collection<TblPcrManifest> tblPcrManifestCollection = new ArrayList<TblPcrManifest>();
	    TblPcrManifest tblPcrManifest = new TblPcrManifest();
	    tblPcrManifest.setId(1);
	    tblPcrManifest.setName("0");
	    tblPcrManifest.setValue("31B97D97B4679917EC3C1D943635693FFBAB4143");
	    tblPcrManifestCollection.add(tblPcrManifest);
	    biosMle.setTblPcrManifestCollection(tblPcrManifestCollection);
		tblHosts.setBiosMleId(biosMle);
		
		String vmmName = "XEN";
		String vmmVersion = "4.3";
		String osName = "Fedora";
		String osVersion = "20";
	    TblMle vmmMle = new TblMle();
	    vmmMle.setId(1);
	    vmmMle.setName(vmmName);
	    vmmMle.setVersion(vmmVersion);
	    TblOs os = new TblOs();
	    os.setId(1);
	    os.setName(osName);
	    os.setVersion(osVersion);
	    vmmMle.setOsId(os);
	    Collection<TblPcrManifest> tblPcrManifestCollectionVMM = new ArrayList<TblPcrManifest>();
        TblPcrManifest tblPcrManifestVMM = new TblPcrManifest();
        tblPcrManifestVMM.setId(2);
        tblPcrManifestVMM.setName("18");
        tblPcrManifestVMM.setValue("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        tblPcrManifestCollection.add(tblPcrManifestVMM);
        vmmMle.setTblPcrManifestCollection(tblPcrManifestCollectionVMM);
        tblHosts.setVmmMleId(vmmMle);
        return tblHosts;
	}
}
