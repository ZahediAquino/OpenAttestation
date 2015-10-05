/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.datatypes;

import com.intel.mtwilson.util.io.UUID;
//import com.intel.mtwilson.datatypes.FilterCriteria;
//import com.intel.mtwilson.datatypes.DefaultFilterCriteria;
//import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;

/**
 *
 * @author ssbangal
 */
public class KvAttributeFilterCriteria extends DefaultFilterCriteria implements FilterCriteria<KvAttribute>{
    
    @QueryParam("id")
    public UUID id;
    @QueryParam("nameEqualTo")
    public String nameEqualTo;
    @QueryParam("nameContains")
    public String nameContains;
    @QueryParam("valueEqualTo")
    public String valueEqualTo;
    @QueryParam("valueContains")
    public String valueContains;
    
}
