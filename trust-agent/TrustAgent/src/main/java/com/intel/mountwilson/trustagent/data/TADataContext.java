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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mountwilson.trustagent.data;

import java.io.File;

import com.intel.mountwilson.common.Config;
import com.intel.mountwilson.common.ErrorCode;
import com.intel.mountwilson.common.HisConfig;

/**
 *
 * @author dsmagadX
 */
public class TADataContext {

    private ErrorCode errorCode = ErrorCode.OK;
    private String selectedPCRs = null;
    private String nonce;
    private String AIKCertificate = null;
    private byte[] tpmQuote = null;
    private String responseXML = null;
    private String osName;
    private String osVersion;
    private String biosOem;
    private String biosVersion;
    private String vmmName;
    private String vmmVersion;
    private String modulesStr;
    private String hostUUID;
    private String assetTagHash;

    public String getBiosOem() {
        return biosOem;
    }

    public void setBiosOem(String biosName) {
        this.biosOem = biosName;
    }

    public String getBiosVersion() {
        return biosVersion;
    }

    public void setBiosVersion(String biosVersion) {
        this.biosVersion = biosVersion;
    }

    public String getVmmName() {
        return vmmName;
    }

    public void setVmmName(String vmmName) {
        this.vmmName = vmmName;
    }

    public String getVmmVersion() {
        return vmmVersion;
    }

    public void setVmmVersion(String vmmVersion) {
        this.vmmVersion = vmmVersion;
    }

    public String getNonceFileName() {
        return getDataFolder() + Config.getInstance().getProperty("nonce.filename");
    }

    public String getResponseXML() {
        return responseXML;
    }

    public String getSelectedPCRs() {
        return selectedPCRs;
    }

    public void setSelectedPCRs(String selectedPCRs) {
        this.selectedPCRs = selectedPCRs;
    }

    public byte[] getTpmQuote() {
        return tpmQuote;
    }

    public void setTpmQuote(byte[] tpmQuote) {
        this.tpmQuote = tpmQuote; //Arrays.copyOf(tpmQuote, tpmQuote.length);
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getQuoteFileName() {
        return getDataFolder() + Config.getInstance().getProperty("aikquote.filename");
    }

    public String getAikBlobFileName() {
        return getCertificateFolder() + Config.getInstance().getProperty("aikblob.filename");
    }

    public String getAikCertFileName() {
        return getCertificateFolder() + Config.getInstance().getProperty("aikcert.filename");
    }

    public String getEKCertFileName() {
        return getCertificateFolder() + Config.getInstance().getProperty("ekcert.filename");
    }

    public String getCertificateFolder() {
        return Config.getHomeFolder() + File.separator + Config.getInstance().getProperty("cert.folder") + File.separator;
    }

    public String getDataFolder() {
        return Config.getHomeFolder() + File.separator + Config.getInstance().getProperty("data.folder") + File.separator;
    }

    public void setAIKCertificate(String certBytes) {
        this.AIKCertificate = certBytes;
    }

    public String getAIKCertificate() {
        return AIKCertificate;
    }

    public void setResponseXML(String responseXML) {
        this.responseXML = responseXML;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public Object getIdentityAuthKey() {

        return HisConfig.getConfiguration().getString("HisIdentityAuth");
    }

    public void setOsName(String osName) {
        this.osName = osName;
    }

    public String getOsName() {
        return osName;
    }

    public void setOsVersion(String osVersion) {
        this.osVersion = osVersion;
    }

    public String getOsVersion() {
        return osVersion;
    }
    
    public File getMeasureLogLaunchScript() {
        if(Config.getInstance().getProperty("modulesScript.filename") != null)
            return new File(Config.getInstance().getProperty("modulesScript.filename"));
        //return new File(Folders.application() + File.separator + "bin" + File.separator + "module_analysis.sh"); // Config.getInstance().getProperty("modulesScript.filename"));
        else
            return new File("");
    }
    
    public File getMeasureLogXmlFile() {
        if(Config.getInstance().getProperty("modulesXml.filename") != null)
            return new File (Config.getInstance().getProperty("modulesXml.filename"));
        //return new File(Folders.repository() + File.separator + "measureLog.xml"); // Config.getInstance().getProperty("modulesXml.filename"));
        else 
            return new File("");
    }
    
    public void setModules(String allModules) {
        this.modulesStr = allModules;
    }

    public String getModules() {
        return modulesStr;
    }
    
     public String getHostUUID() {
     return hostUUID;
    }
    public void setHostUUID(String hostUUID) {
        this.hostUUID = hostUUID;
    }
    
    public String getAssetTagHash() {
        return assetTagHash;
    }
    
    public void setAssetTagHash(String assetTagHash) {
        this.assetTagHash = assetTagHash;
    }

}
