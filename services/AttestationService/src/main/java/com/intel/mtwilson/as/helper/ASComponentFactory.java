/*
 * Copyright (c) 2013, Intel Corporation. 
 * All rights reserved.
 * 
 * The contents of this file are released under the BSD license, you may not use this file except in compliance with the License.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of Intel Corporation nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.intel.mtwilson.as.helper;

import com.intel.mtwilson.as.business.HostBO;
import com.intel.mtwilson.as.business.ReportsBO;
import com.intel.mtwilson.as.business.trust.HostTrustBO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jbuhacoff
 */
public class ASComponentFactory {
    private static Logger log = LoggerFactory.getLogger(ASComponentFactory.class);
    
    private static Object load(String premiumClassName) {
        Object premium = null;
        try {
            Class premiumClass = Class.forName(premiumClassName);
            premium = premiumClass.newInstance();
        } catch (InstantiationException e) {
            log.error("Cannot load class: "+e.toString());
        } catch (IllegalAccessException e) {
            log.error("Cannot load class: "+e.toString());
        } catch(ClassNotFoundException e) {
            log.info("Class not found: "+e.toString());
        }
        return premium;
    }

    public HostBO getHostBO() {
        Object premium = load("com.intel.mtwilson.as.premium.PremiumHostBO");
        HostBO bean;
        if( premium != null ) {            
            bean = (HostBO)premium;
        }
        else {
            bean = new HostBO();
        }
        return bean;
    }

    public HostTrustBO getHostTrustBO() {
        Object premium = load("com.intel.mtwilson.as.premium.PremiumHostTrustBO");
        HostTrustBO bean;
        if( premium != null ) {            
            bean = (HostTrustBO)premium;
        }
        else {
            bean = new HostTrustBO();
        }
        HostBO hostBO = getHostBO();
        bean.setHostBO(hostBO);
        return bean;
    }
    
     public ReportsBO getReportsBO() {
        Object premium = load("com.intel.mtwilson.as.premium.PremiumReportsBO");
        ReportsBO bean;
        if( premium != null ) {            
            bean = (ReportsBO)premium;
        }
        else {
            bean = new ReportsBO();
        }
        return bean;
    }
     
     public static HostBO getHostBO1() {
        HostBO bean = new HostBO();
        return bean;
    }

    public static HostTrustBO getHostTrustBO1() {
        HostTrustBO bean = new HostTrustBO();
        HostBO hostBO = getHostBO1();
        bean.setHostBO(hostBO);
        return bean;
    }
    
     public static ReportsBO getReportsBO1() {
        ReportsBO bean = new ReportsBO();
        return bean;
    }
}
