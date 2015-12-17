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

import com.intel.mtwilson.as.controller.TblOemJpaController;
import com.intel.mtwilson.as.data.TblOem;
import com.intel.mtwilson.datatypes.OemData;

@RunWith(MockitoJUnitRunner.class)
public class OemBOTest {
	@Mock
    private TblOemJpaController tblOemJpaController;
    
    @Mock
    private EntityManagerFactory emf;
    
    @Spy
    private OemBO oemBO = new OemBO(); 
    
    private int OEM_ID1 = 1;
    
    private int OEM_ID2 = 2;

	@Before
	public void setUp() throws Exception {
		doReturn(emf).when(oemBO).getEntityManagerFactory();
       //doReturn(tblOemJpaController).when(oemBO).getTblOemJpaController();
	}

	@After
	public void tearDown() throws Exception {
		if (emf != null)
            emf.close();
	}

	@Test
	public void testGetAllOem() {
		List<TblOem> allRecords = new ArrayList<TblOem>();
        TblOem tblOem1 = new TblOem(OEM_ID1);
        TblOem tblOem2 = new TblOem(OEM_ID2);
        allRecords.add(tblOem1);
        allRecords.add(tblOem2);
        doReturn(allRecords).when(tblOemJpaController).findTblOemEntities();
        List<OemData> allData = oemBO.getAllOem();
        assertNotNull(allData);
        assertEquals(2,allData.size());
	}

	@Test
	public void testUpdateOem() {
        TblOem tblOem = new TblOem(OEM_ID1);
        doReturn(tblOem).when(tblOemJpaController).findTblOemByName(anyString());
        OemData oemData = new OemData("DELL", "");
        String result = oemBO.updateOem(oemData);
    	assertEquals("true", result);
	}

	@Test
	public void testCreateOem() {
		TblOem tblOem = null;
        doReturn(tblOem).when(tblOemJpaController).findTblOemByName(anyString());
        OemData oemData = new OemData("DELL", "");
        String result = oemBO.createOem(oemData);
    	assertEquals("true", result);
	}

	@Test
	public void testDeleteOem() {
		TblOem tblOem = new TblOem(OEM_ID1);
		tblOem.setName("DELL");
        doReturn(tblOem).when(tblOemJpaController).findTblOemByName(anyString());
        String result = oemBO.deleteOem(tblOem.getName());
    	assertEquals("true", result);
	}
}
