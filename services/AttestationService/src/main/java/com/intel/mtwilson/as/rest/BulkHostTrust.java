/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.as.rest;

import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.business.trust.BulkHostTrustBO;
import com.intel.mtwilson.util.validation.ValidationUtil;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jlopezgu
 */
//@Path("/AttestationService/resources/hosts/bulk")
@Path("/hosts/bulk")
public class BulkHostTrust {
     private Logger log = LoggerFactory.getLogger(getClass());

        /**
         * REST Web Service Example: GET /hosts/trust?hosts=host_name_1
         * ,host_name_2,host_name_3&force_verify=true
         *
         * @param hosts
         * @param forceVerify
     * @param timeout
         * @return
         */
        @GET
        @Produces({MediaType.APPLICATION_XML})
        @Path("/trust/saml")
        //@RolesAllowed({"Attestation", "Report"})
        @RequiresPermissions("host_attestations:create,retrieve")
        public String getTrustSaml(
                @QueryParam("hosts") String hosts,
                @QueryParam("force_verify") @DefaultValue("false") Boolean forceVerify,
                //                        @QueryParam("threads") @DefaultValue("5") Integer threads, // bug #503 max threads now global and configured in properties file
                @QueryParam("timeout") @DefaultValue("600") Integer timeout) {
            
                ValidationUtil.validate(hosts);
                Integer myTimeOut = timeout;
                // if no timeout value is passed to function, check config for default, 
                // if not in config, go with default value
                // Modified the default time out back to 600 seconds as we are seeing time out issues. 30 seconds short for VMware hosts.
                if (timeout == 600) {
                        log.info("getTrustSaml called with default timeout, checking config");
                        myTimeOut = ASConfig.getConfiguration().getInt("com.intel.mountwilson.as.attestation.hostTimeout", 600);
                        log.debug("getTrustSaml config returned back" + myTimeOut);
                }
                if (hosts == null || hosts.length() == 0) {

                        throw new ASException(com.intel.mtwilson.datatypes.ErrorCode.AS_MISSING_INPUT,
                                "hosts");
                }

                Set<String> hostSet = new HashSet<String>();
                // bug #783  make sure that we only pass to the next layer hostnames that are likely to be valid 
                for(String host : Arrays.asList(hosts.split(","))) {
                    log.debug("Host: '{}'", host);
                    if( !(host.trim().isEmpty() || host.trim() == null) ) {
                        hostSet.add(host.trim());
                    }
                }
                BulkHostTrustBO bulkHostTrustBO = new BulkHostTrustBO(/*threads, */myTimeOut);
                String result =  bulkHostTrustBO.getBulkTrustSaml(hostSet, forceVerify);
//                log.info("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< " 
//                        + result 
//                        + ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
                
                return result;


        }
}
