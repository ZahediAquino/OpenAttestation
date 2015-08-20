package com.intel.mtwilson.as.business;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManagerFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import static org.mockito.Mockito.when;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.doReturn;

import com.intel.mountwilson.as.hostmanifestreport.data.HostManifestReportType;
import com.intel.mountwilson.as.hosttrustreport.data.HostsTrustReportType;
import com.intel.mountwilson.manifest.IManifestStrategy;
import com.intel.mountwilson.manifest.IManifestStrategyFactory;
import com.intel.mtwilson.as.controller.TblHostsJpaController;
import com.intel.mtwilson.as.controller.TblTaLogJpaController;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblOem;
import com.intel.mtwilson.as.data.TblOs;
import com.intel.mtwilson.as.data.TblPcrManifest;
import com.intel.mtwilson.as.data.TblTaLog;
import com.intel.mtwilson.datatypes.AttestationReport;
import com.intel.mtwilson.util.net.Hostname;
import java.io.IOException;

@RunWith(MockitoJUnitRunner.class)
public class ReportsBOTest {
	@Spy
	private ReportsBO reportsBO= new ReportsBO();
	
	@Mock
	private TblHostsJpaController tblHostsJpaController;

	@Mock
	private TblTaLogJpaController tblTaLogJpaController;
	
	@Mock
	IManifestStrategyFactory strategyFactory;
	
	@Mock
	private IManifestStrategy manifestStrategy;
	
	@Mock
	private EntityManagerFactory emf;
	
	private static final String SERVER_NAME = "testserver";
	
	@Before
	public void setUp() throws Exception {
		doReturn(emf).when(reportsBO).getEntityManagerFactory();
		doReturn(tblHostsJpaController).when(reportsBO).getTblHostsJpaController();
		doReturn(tblTaLogJpaController).when(reportsBO).getTblTaLogJpaController();
		doReturn(strategyFactory).when(reportsBO).getManifestStrategyFactory();
    	doReturn(manifestStrategy).when(reportsBO).getManifestStrategy(any(TblHosts.class));
	}

	@Test
	public void testGetTrustReportNoError() {
		Collection<Hostname> hostNames = new ArrayList<Hostname>();
		hostNames.add(new Hostname(SERVER_NAME));
		when(tblHostsJpaController.findByName(anyString())).thenReturn(mockFindByName());
		when(tblTaLogJpaController.findTrustStatusByHostId(anyInt(), anyInt())).thenReturn(null);
		HostsTrustReportType hostsTrustReportType = reportsBO.getTrustReport(hostNames);
		assertNotNull(hostsTrustReportType);
		assertFalse(hostsTrustReportType.getHost().size() > 0);
	}
	
	@Test
	public void testGetTrustReportWithError() {
		Collection<Hostname> hostNames = new ArrayList<Hostname>();
		hostNames.add(new Hostname(SERVER_NAME));
		when(tblHostsJpaController.findByName(anyString())).thenReturn(mockFindByName());
		List<TblTaLog> taLogs = new ArrayList<TblTaLog>();
		TblTaLog taLog1 = new TblTaLog(Integer.valueOf(1), 1, 1, "0", "31B97D97B4679917EC3C1D943635693FFBAB4143", false, new Date());
		TblTaLog taLog2 = new TblTaLog(Integer.valueOf(2), 1, 2, "18", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", false, new Date());
		taLog1.setError("BIOS:1,VMM:1");
		taLog2.setError("BIOS:1,VMM:1");
		taLogs.add(taLog1);
		taLogs.add(taLog2);
		when(tblTaLogJpaController.findTrustStatusByHostId(anyInt(), anyInt())).thenReturn(taLogs);
		HostsTrustReportType hostsTrustReportType = reportsBO.getTrustReport(hostNames);
		assertNotNull(hostsTrustReportType);
		assertTrue(hostsTrustReportType.getHost().size() > 0);
	}

	@Test
	public void testGetReportManifest() {
		when(tblHostsJpaController.findByName(anyString())).thenReturn(mockFindByName());
		when(tblTaLogJpaController.findLastStatusTs(any(Integer.class))).thenReturn(new Date());
		List<TblTaLog> taLogs = new ArrayList<TblTaLog>();
		taLogs.add(new TblTaLog(Integer.valueOf(1), 1, 1, "0", "31B97D97B4679917EC3C1D943635693FFBAB4143", true, new Date()));
		when(tblTaLogJpaController.findLogsByHostId(anyInt(), any(Date.class))).thenReturn(taLogs);
		HostManifestReportType hostManifestReportType = reportsBO.getReportManifest(new Hostname(SERVER_NAME));
		assertNotNull(hostManifestReportType);
		assertNotNull(hostManifestReportType.getHost());
	}

	@Test
	public void testGetHostAttestationReport() {
		when(tblHostsJpaController.findByName(anyString())).thenReturn(mockFindByName());
		String attestationReport = reportsBO.getHostAttestationReport(new Hostname(SERVER_NAME));
		assertNotNull(attestationReport);
		assertFalse(attestationReport.equalsIgnoreCase(""));
	}

	@Test
	public void testGetAttestationReport() throws NumberFormatException, IOException {
		when(tblHostsJpaController.findByName(anyString())).thenReturn(mockFindByName());
		when(tblTaLogJpaController.findLastStatusTs(any(Integer.class))).thenReturn(new Date());
		List<TblTaLog> taLogs = new ArrayList<TblTaLog>();
		taLogs.add(new TblTaLog(Integer.valueOf(1), 1, 1, "18", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", true, new Date()));
		when(tblTaLogJpaController.findLogsByHostId(anyInt(), any(Date.class))).thenReturn(taLogs);
		AttestationReport attestationReport = reportsBO.getAttestationReport(new Hostname(SERVER_NAME), false);
		assertNotNull(attestationReport);
		assertTrue(attestationReport.getPcrLogs().size()>0);
	}

	public TblHosts mockFindByName() {
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
        tblPcrManifestCollectionVMM.add(tblPcrManifestVMM);
        vmmMle.setTblPcrManifestCollection(tblPcrManifestCollectionVMM);
        tblHosts.setVmmMleId(vmmMle);
        return tblHosts;
	}

}
