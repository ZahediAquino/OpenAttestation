package com.intel.mtwilson.as.business;

import static org.junit.Assert.*;
import static org.mockito.Mockito.doReturn;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.persistence.EntityManagerFactory;

import static org.mockito.Mockito.when;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.doReturn;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.intel.mountwilson.manifest.data.IManifest;
import com.intel.mountwilson.manifest.data.PcrManifest;
import com.intel.mtwilson.agent.HostAgent;
import com.intel.mtwilson.agent.HostAgentFactory;
import com.intel.mtwilson.as.controller.TblHostsJpaController;
import com.intel.mtwilson.as.controller.TblMleJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblOem;
import com.intel.mtwilson.as.data.TblOs;
import com.intel.mtwilson.as.data.TblPcrManifest;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.crypto.CryptographyException;
import com.intel.mtwilson.crypto.RsaUtil;
import com.intel.mtwilson.datatypes.HostTrustStatus;
import com.intel.mtwilson.util.net.Hostname;
import com.intel.mtwilson.datatypes.TxtHost;
import com.intel.mtwilson.datatypes.TxtHostRecord;

@RunWith(MockitoJUnitRunner.class)
public class HostBOTest {

	@Spy
	private HostBO hostBO = new HostBO();
	
	@Mock
	private TblHostsJpaController hostsJpaController;
	
	@Mock
	private EntityManagerFactory emf;
	
	@Mock
	private TblMleJpaController mleJpaController;
	
	@Mock
	private HostAgentFactory haf;
	
	@Mock
	private HostAgent agent;
	
	@Mock
	private TblTaLogJpaController taLogJpaController; 
	
	private static final String SERVER_NAME = "127.0.0.1";
	
	@Before
	public void setUp() throws Exception {
		doReturn(emf).when(hostBO).getEntityManagerFactory();
    	doReturn(hostsJpaController).when(hostBO).getHostsJpaController();
    	doReturn(mleJpaController).when(hostBO).getMleJpaController();
    	doReturn(haf).when(hostBO).getHostAgentFactory();
    	doReturn(agent).when(hostBO).getHostAgent(any(TblHosts.class));
    	doReturn(taLogJpaController).when(hostBO).getTaLogJpaController();
	}

	@Test
	public void testAddHost() {
		TxtHost host = mockHost();
		when(hostsJpaController.findByName(anyString())).thenReturn(null);
		when(hostsJpaController.findByIPAddress(anyString())).thenReturn(null);
		TblMle biosMle = new TblMle(1, "DELL", "A08", "PCR", "BIOS", "0");
		TblMle vmmMle = new TblMle(2, "XEN", "4.3", "PCR", "VMM", "18");
		when(mleJpaController.findBiosMle(anyString(), anyString(), anyString())).thenReturn(biosMle);
		when(mleJpaController.findVmmMle(anyString(), anyString(), anyString(), anyString())).thenReturn(vmmMle);
		String response = hostBO.addHost(host);
		assertTrue(response.equalsIgnoreCase("true"));
	}

	@Test
	public void testUpdateHost() throws CryptographyException {
		doReturn(mockGetHost()).when(hostBO).getHostByName(new Hostname(SERVER_NAME));
		when(mleJpaController.findBiosMle(anyString(),anyString(),anyString())).thenReturn(mockGetHost().getBiosMleId());
		when(mleJpaController.findVmmMle(anyString(), anyString(), anyString(), anyString())).thenReturn(mockGetHost().getBiosMleId());
		String response = hostBO.updateHost(mockHost());
		assertTrue(response.equalsIgnoreCase("true"));
	}

	@Test
	public void testDeleteHost() throws CryptographyException {
		List<TblTaLog> taLogs = new ArrayList<TblTaLog>();
		taLogs.add(new TblTaLog(1));
		taLogs.add(new TblTaLog(2));
		when(taLogJpaController.findLogsByHostId(anyInt(), any(Date.class))).thenReturn(taLogs);
		doReturn(new TblHosts(1)).when(hostBO).getHostByName(new Hostname(SERVER_NAME));
		String response = hostBO.deleteHost(new Hostname(SERVER_NAME));
		assertTrue(response.equalsIgnoreCase("true"));
	}

	public TxtHost mockHost() {
		TxtHostRecord hostRecord = new TxtHostRecord();
		HostTrustStatus trustStatus = new HostTrustStatus();
		hostRecord.HostName = SERVER_NAME;
		hostRecord.IPAddress = SERVER_NAME;
		hostRecord.BIOS_Name = "DELL";
		hostRecord.BIOS_Version = "A08";
		hostRecord.BIOS_Oem = "DELL";
		hostRecord.VMM_Name = "XENESX";
		hostRecord.VMM_Version = "4.3";
		hostRecord.VMM_OSName = "Fedora";
		hostRecord.VMM_OSVersion = "20";
		hostRecord.AddOn_Connection_String = "intel:https://" +SERVER_NAME +":9999";
		hostRecord.Port = Integer.valueOf(9999);
		trustStatus.bios = true;
		trustStatus.vmm = true;
		TxtHost host = new TxtHost(hostRecord, trustStatus);
        return host;
	}
	
	public TblHosts mockGetHost() {
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
        
        tblHosts.setTlsPolicyName("");
        tblHosts.setPort(8181);
        return tblHosts;
	}
		
}
