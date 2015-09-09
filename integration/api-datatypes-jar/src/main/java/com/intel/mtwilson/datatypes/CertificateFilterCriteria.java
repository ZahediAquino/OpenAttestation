/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.datatypes;

import com.intel.mtwilson.util.crypto.Sha1Digest;
import com.intel.mtwilson.util.crypto.Sha256Digest;
import com.intel.mtwilson.util.io.UUID;
import com.intel.mtwilson.util.io.Iso8601Date;
//import com.intel.mtwilson.datatypes.FilterCriteria;
//import com.intel.mtwilson.datatypes.DefaultFilterCriteria;
import java.util.Date;
import javax.ws.rs.QueryParam;
import com.intel.mtwilson.util.validation.Regex;
import com.intel.mtwilson.util.validation.RegexPatterns;
import com.intel.mtwilson.util.validation.Unchecked;


/**
 *
 * @author ssbangal
 */
public class CertificateFilterCriteria extends DefaultFilterCriteria implements FilterCriteria<Certificate>{

    @QueryParam("id")
    public UUID id;
    @QueryParam("subjectEqualTo")
    public String subjectEqualTo;
    @QueryParam("subjectContains")
    public String subjectContains;
    @QueryParam("issuerEqualTo")
    @Regex(RegexPatterns.ANY_VALUE)    
    public String issuerEqualTo;
    @QueryParam("issuerContains")
    @Regex(RegexPatterns.ANY_VALUE)    
    public String issuerContains;
    @QueryParam("statusEqualTo")
    public String statusEqualTo;
    @QueryParam("validOn")
    public Iso8601Date validOn;
    @QueryParam("validBefore")
    public Iso8601Date validBefore;
    @QueryParam("validAfter")
    public Iso8601Date validAfter;
    @Unchecked
    @QueryParam("sha1")
    public Sha1Digest sha1;
    @Unchecked
    @QueryParam("sha256")
    public Sha256Digest sha256;
    @QueryParam("revoked")
    public Boolean revoked;
    
}
