package com.intel.mtwilson.wlm.business;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.persistence.EntityManagerFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.intel.mtwilson.as.controller.MwMleSourceJpaController;
import com.intel.mtwilson.as.controller.TblMleJpaController;
import com.intel.mtwilson.as.controller.TblOemJpaController;
import com.intel.mtwilson.as.controller.TblOsJpaController;
import com.intel.mtwilson.as.controller.TblPcrManifestJpaController;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.as.data.TblOem;
import com.intel.mtwilson.as.data.TblOs;
import com.intel.mtwilson.as.data.TblPcrManifest;
import com.intel.mtwilson.datatypes.ManifestData;
import com.intel.mtwilson.datatypes.MleData;
import com.intel.mtwilson.datatypes.PCRWhiteList;
import com.intel.mtwilson.datatypes.MleData.AttestationType;
import com.intel.mtwilson.datatypes.MleData.MleType;

@RunWith(MockitoJUnitRunner.class)
public class MleBOTest {
	@Mock
    private TblMleJpaController tblMleJpaController;
    
	@Mock
    private TblPcrManifestJpaController tblPcrManifestJpaController;
	
	@Mock
    private TblOemJpaController tblOemJpaController;
	
	@Mock
    private TblOsJpaController tblOsJpaController;
	
	@Mock
	private MwMleSourceJpaController mleSourceJpaController;
	
    @Mock
    private EntityManagerFactory emf;
    
    @Spy
    private MleBO mleBO = new MleBO(); 
    
    private int MLE_ID1 = 1;
    
    private int MLE_ID2 = 2;
    
    private int OEM_ID = 1;
    
    private int OS_ID = 1;
    
    private int PcrManifest_ID1 = 1;
    
    private int PcrManifest_ID2 = 2;

	@Before
	public void setUp() throws Exception {
		doReturn(emf).when(mleBO).getEntityManagerFactory();
        /*doReturn(tblMleJpaController).when(mleBO).getTblMleJpaController();
        doReturn(tblPcrManifestJpaController).when(mleBO).getTblPcrManifestJpaController();
        doReturn(tblOemJpaController).when(mleBO).getTblOemJpaController();
        doReturn(tblOsJpaController).when(mleBO).getTblOsJpaController();
        doReturn(mleSourceJpaController).when(mleBO).getMleSourceJpaController();*/
	}

	@After
	public void tearDown() throws Exception {
		if (emf != null)
            emf.close();
	}

	@Test
	public void testAddMLe() {
		TblMle biosMle = null;
		TblMle vmmMle = null;
		TblOem tblOem = new TblOem();
		tblOem.setId(OEM_ID);
		tblOem.setName("DELL");
		TblOs tblOs = new TblOs(OS_ID, "Fedora", "20");
		doReturn(tblOem).when(tblOemJpaController).findTblOemByName(anyString());
		doReturn(tblOs).when(tblOsJpaController).findTblOsByNameVersion(anyString(), anyString());
		doReturn(biosMle).when(tblMleJpaController).findBiosMle(anyString(), anyString(), anyString());
		doReturn(vmmMle).when(tblMleJpaController).findVmmMle(anyString(), anyString(), anyString(), anyString());
		List<ManifestData> biosManifestList = new ArrayList<ManifestData>();
		biosManifestList.add(new ManifestData("0", "31B97D97B4679917EC3C1D943635693FFBAB4143"));
        MleData biosMleData = new MleData("DELL", "A08", MleType.BIOS, AttestationType.PCR, biosManifestList, "", "", "", "DELL");
        List<ManifestData> vmmManifestList = new ArrayList<ManifestData>();
		vmmManifestList.add(new ManifestData("18", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
		MleData vmmMleData = new MleData("XEN", "4.3", MleType.VMM, AttestationType.PCR, vmmManifestList, "", "Fedora", "20", "");
		String biosResult = mleBO.addMLe(biosMleData);
    	assertEquals("true", biosResult);
    	String vmmResult = mleBO.addMLe(vmmMleData);
    	assertEquals("true", vmmResult);
	}

	@Test
	public void testUpdateMle() {
		TblMle biosMle = new TblMle(MLE_ID1, "DELL", "A08", "PCR", "BIOS", "0");
		TblMle vmmMle = new TblMle(MLE_ID2, "XEN", "4.3", "PCR", "VMM", "18");
		doReturn(biosMle).when(tblMleJpaController).findBiosMle(anyString(), anyString(), anyString());
		doReturn(vmmMle).when(tblMleJpaController).findVmmMle(anyString(), anyString(), anyString(), anyString());
		List<ManifestData> biosManifestList = new ArrayList<ManifestData>();
		biosManifestList.add(new ManifestData("0", "31B97D97B4679917EC3C1D943635693FFBAB4143"));
        MleData biosMleData = new MleData("DELL", "A08", MleType.BIOS, AttestationType.PCR, biosManifestList, "", "", "", "DELL");
        List<ManifestData> vmmManifestList = new ArrayList<ManifestData>();
		vmmManifestList.add(new ManifestData("18", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));
		MleData vmmMleData = new MleData("XEN", "4.3", MleType.VMM, AttestationType.PCR, vmmManifestList, "", "Fedora", "20", "");
		String biosResult = mleBO.updateMle(biosMleData);
        assertEquals("true", biosResult);
        String vmmResult = mleBO.updateMle(vmmMleData);
    	assertEquals("true", vmmResult);
	}

	@Test
	public void testDeleteMle() {
		TblMle biosMle = mockFindBiosMle();
		TblMle vmmMle = mockFindVmmMle();
		doReturn(mockFindBiosMle()).when(tblMleJpaController).findBiosMle(anyString(), anyString(), anyString());
		doReturn(mockFindVmmMle()).when(tblMleJpaController).findVmmMle(anyString(), anyString(), anyString(), anyString());
		String biosResult = mleBO.deleteMle(biosMle.getName(), biosMle.getVersion(), biosMle.getOsId().getName(), 
				biosMle.getOsId().getVersion(), biosMle.getOemId().getName());
		assertEquals("true", biosResult);
		String vmmResult = mleBO.deleteMle(vmmMle.getName(), vmmMle.getVersion(), vmmMle.getOsId().getName(), 
				vmmMle.getOsId().getVersion(), vmmMle.getOemId().getName());
		assertEquals("true", vmmResult);
	}

	@Test
	public void testAddPCRWhiteList() {
		PCRWhiteList biosPcrData = new PCRWhiteList("0", "31B97D97B4679917EC3C1D943635693FFBAB4143", "DELL", "A08",
				"", "", "DELL");
		PCRWhiteList vmmPcrData = new PCRWhiteList("18", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "XEN", "4.3",
				"Fedora", "20", "");
		doReturn(new TblMle(MLE_ID1, "DELL", "A08", "PCR", "BIOS", "0")).when(tblMleJpaController).findBiosMle(biosPcrData.getMleName(), 
				biosPcrData.getMleVersion(), biosPcrData.getOemName());
		doReturn(new TblMle(MLE_ID2, "XEN", "4.3", "PCR", "VMM", "18")).when(tblMleJpaController).findVmmMle(vmmPcrData.getMleName(), 
				vmmPcrData.getMleVersion(), vmmPcrData.getOsName(), vmmPcrData.getOsVersion());
		doReturn(null).when(tblPcrManifestJpaController).findByMleIdName(MLE_ID1, biosPcrData.getPcrName());
		doReturn(null).when(tblPcrManifestJpaController).findByMleIdName(MLE_ID2,vmmPcrData.getPcrName());
		String biosResult = mleBO.addPCRWhiteList(biosPcrData);
		assertEquals("true", biosResult);
		String vmmResult = mleBO.addPCRWhiteList(vmmPcrData);
		assertEquals("true", vmmResult);
		
	}

	@Test
	public void testUpdatePCRWhiteList() {
		PCRWhiteList biosPcrData = new PCRWhiteList("0", "31B97D97B4679917EC3C1D943635693FFBAB4143", "DELL", "A08",
				"", "", "DELL");
		PCRWhiteList vmmPcrData = new PCRWhiteList("18", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "XEN", "4.3",
				"Fedora", "20", "");
		doReturn(new TblMle(MLE_ID1, "DELL", "A08", "PCR", "BIOS", "0")).when(tblMleJpaController).findBiosMle(biosPcrData.getMleName(), 
				biosPcrData.getMleVersion(), biosPcrData.getOemName());
		doReturn(new TblMle(MLE_ID2, "XEN", "4.3", "PCR", "VMM", "18")).when(tblMleJpaController).findVmmMle(vmmPcrData.getMleName(), 
				vmmPcrData.getMleVersion(), vmmPcrData.getOsName(), vmmPcrData.getOsVersion());
		doReturn(new TblPcrManifest(PcrManifest_ID1, biosPcrData.getPcrName(), biosPcrData.getPcrDigest()))
		        .when(tblPcrManifestJpaController).findByMleIdName(MLE_ID1, biosPcrData.getPcrName());
		doReturn(new TblPcrManifest(PcrManifest_ID2, vmmPcrData.getPcrName(), vmmPcrData.getPcrDigest()))
		        .when(tblPcrManifestJpaController).findByMleIdName(MLE_ID2,vmmPcrData.getPcrName());
		String biosResult = mleBO.updatePCRWhiteList(biosPcrData);
		assertEquals("true", biosResult);
		String vmmResult = mleBO.updatePCRWhiteList(vmmPcrData);
		assertEquals("true", vmmResult);
	}

	@Test
	public void testDeletePCRWhiteList() {
		doReturn(new TblMle(MLE_ID1, "DELL", "A08", "PCR", "BIOS", "0")).when(tblMleJpaController).findBiosMle("DELL", "A08", "DELL");
		doReturn(new TblMle(MLE_ID2, "XEN", "4.3", "PCR", "VMM", "18")).when(tblMleJpaController).findVmmMle("XEN", "4.3", "Fedora", "20");
		doReturn(new TblPcrManifest(PcrManifest_ID1, "0", "31B97D97B4679917EC3C1D943635693FFBAB4143")).when(tblPcrManifestJpaController).findByMleIdName(MLE_ID1, "0");
		doReturn(new TblPcrManifest(PcrManifest_ID2, "18", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")).when(tblPcrManifestJpaController).findByMleIdName(MLE_ID2, "18");
		String biosResult = mleBO.deletePCRWhiteList("0", "DELL", "A08", "", "", "DELL");
		assertEquals("true", biosResult);
		String vmmResult = mleBO.deletePCRWhiteList("18", "XEN", "4.3", "Fedora", "20", "");
		assertEquals("true", vmmResult);
	}

	public TblMle mockFindBiosMle() {
		String biosName = "DELL";
		String biosVersion = "A08";
		String oemName = "DELL";
	    TblMle biosMle = new TblMle();
	    biosMle.setId(MLE_ID1);
	    biosMle.setName(biosName);
	    biosMle.setVersion(biosVersion);
	    TblOem oem = new TblOem();
	    oem.setId(1);
	    oem.setName(oemName);
	    biosMle.setOemId(oem);
	    biosMle.setOsId(new TblOs());
	    Collection<TblPcrManifest> tblPcrManifestCollection = new ArrayList<TblPcrManifest>();
	    TblPcrManifest tblPcrManifest = new TblPcrManifest();
	    tblPcrManifest.setId(1);
	    tblPcrManifest.setName("0");
	    tblPcrManifest.setValue("31B97D97B4679917EC3C1D943635693FFBAB4143");
	    tblPcrManifestCollection.add(tblPcrManifest);
	    biosMle.setTblPcrManifestCollection(tblPcrManifestCollection);
	    return biosMle;
	}
	
	public TblMle mockFindVmmMle() {
		String vmmName = "XEN";
		String vmmVersion = "4.3";
		String osName = "Fedora";
		String osVersion = "20";
	    TblMle vmmMle = new TblMle();
	    vmmMle.setId(MLE_ID2);
	    vmmMle.setName(vmmName);
	    vmmMle.setVersion(vmmVersion);
	    vmmMle.setOemId(new TblOem());
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
        return vmmMle;
	}
}
