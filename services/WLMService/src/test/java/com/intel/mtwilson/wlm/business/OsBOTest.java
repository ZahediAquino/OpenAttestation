package com.intel.mtwilson.wlm.business;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManagerFactory;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import com.intel.mtwilson.as.controller.TblOsJpaController;
import com.intel.mtwilson.as.data.TblOs;
import com.intel.mtwilson.datatypes.OsData;

@RunWith(MockitoJUnitRunner.class)
public class OsBOTest {
    @Mock
    private TblOsJpaController tblOsJpaController;
    
    @Mock
    private EntityManagerFactory emf;
    
    @Spy
    private OsBO osBO = new OsBO(); 
    
    private int OS_ID1 = 1;
    
    private int OS_ID2 = 2;
    
    @Before
    public void setUp() throws Exception {
        doReturn(emf).when(osBO).getEntityManagerFactory();
        //doReturn(tblOsJpaController).when(osBO).getTblOsJpaController();
    }

    @After
    public void tearDown() throws Exception {
        if (emf != null)
            emf.close();
    }

    @Test
    public void testGetAllOs() {
        List<TblOs> allRecords = new ArrayList<TblOs>();
        TblOs tblOs1 = new TblOs(OS_ID1, "Fedora", "20");
        TblOs tblOs2 = new TblOs(OS_ID2, "Fedora", "19");
        allRecords.add(tblOs1);
        allRecords.add(tblOs2);
        doReturn(allRecords).when(tblOsJpaController).findTblOsEntities();
        List<OsData> allData = osBO.getAllOs();
        assertNotNull(allData);
        assertEquals(2,allData.size());
    }

    @Test
    public void testUpdateOs() {
    	TblOs tblOs = new TblOs(OS_ID1, "Fedora", "20");
    	doReturn(tblOs).when(tblOsJpaController).findTblOsByNameVersion(anyString(), anyString());
    	OsData osData = new OsData("Fedora", "20", "");
    	String result = osBO.updateOs(osData);
    	assertEquals("true", result);
    }

    @Test
    public void testCreateOs() {
    	TblOs tblOs = null;
    	doReturn(tblOs).when(tblOsJpaController).findTblOsByNameVersion(anyString(), anyString());
    	OsData osData = new OsData("Fedora", "20", "");
    	String result = osBO.createOs(osData);
    	assertEquals("true", result);
    }

    @Test
    public void testDeleteOs() {
    	TblOs tblOs = new TblOs(OS_ID1, "Fedora", "20");
    	doReturn(tblOs).when(tblOsJpaController).findTblOsByNameVersion(anyString(), anyString());
    	String result = osBO.deleteOs(tblOs.getName(), tblOs.getVersion());
    	assertEquals("true", result);
    }
}
