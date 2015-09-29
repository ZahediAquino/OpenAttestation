/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.saml;

import com.intel.mtwilson.util.configuration.CommonsConfigurationAdapter;
import com.intel.mtwilson.util.configuration.Configuration;


/**
 * THIS CLASS IS TENTATIVE - NOT CURENTLY BEING USED OUTSIDE THIS PACKAGE
 * 
 * The setters are not defined because if some part of the application 
 * needs to change the saml keystore password, or the alias, etc. then
 * it cannot just change those settings and save the configuration because
 * things will cease to work. Those changes need to be done by a setup task
 * that knows to save the keystore with a new password, or to archive the
 * old certificate, etc. 
 * 
 * @author jbuhacoff
 */
public class SamlConfiguration {
    public static final String JSR105_PROVIDER = "jsr105Provider"; // default provider is "org.jcp.xml.dsig.internal.dom.XMLDSigRI"
    public static final String SAML_KEYSTORE_FILE = "saml.keystore.file";
    public static final String SAML_KEYSTORE_PASSWORD = "saml.keystore.password";
    public static final String SAML_KEY_ALIAS = "saml.key.alias";
    public static final String SAML_KEY_PASSWORD = "saml.key.password";
    public static final String SAML_ISSUER = "saml.issuer"; // saml.certificate.dn 
    public static final String SAML_VALIDITY_SECONDS = "saml.validity.seconds";
    
    private org.apache.commons.configuration.Configuration conf;
    
    public SamlConfiguration(Configuration configuration) {
        conf = new CommonsConfigurationAdapter(configuration);
    }

    public String getJsr105Provider() { 
        return conf.getString(JSR105_PROVIDER, "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
    }
    
    
    public String getSamlIssuer() { 
        return conf.getString(SAML_ISSUER); // intentionally no default here;  maybe this one needs to be renamed because its not clear whether we mean the SAML CA CERT DN or the SAML "Issuer" attribute which could be a URL
    }
    
    public Integer getSamlValiditySeconds() {
        return conf.getInteger(SAML_VALIDITY_SECONDS, 3600);
    }
    
    public String getSamlKeyAlias() {
        return conf.getString(SAML_KEY_ALIAS);
    }
    
    public String getSamlKeyPassword() {
        return conf.getString(SAML_KEY_PASSWORD); // intentionally no default because it must be randomly generated on each install, although this may be set to the same value as the randomly generated keystore password
    }

    public String getSamlKeystoreFile() {
        return conf.getString(SAML_KEYSTORE_FILE);
    }

    public String getSamlKeystorePassword() {
        return conf.getString(SAML_KEYSTORE_PASSWORD); // intentionally no default because it must be randomly generated on each install
    }

}
