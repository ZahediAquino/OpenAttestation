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
package com.intel.mtwilson.as.data;

import com.intel.mtwilson.util.io.ByteArrayResource;
import com.intel.mtwilson.util.io.Resource;
import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import javax.persistence.*;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import org.eclipse.persistence.annotations.Customizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dsmagadx
 */
@Entity
@Table(name = "mw_hosts")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "TblHosts.findAll", query = "SELECT t FROM TblHosts t"),
    @NamedQuery(name = "TblHosts.findById", query = "SELECT t FROM TblHosts t WHERE t.id = :id"),
    @NamedQuery(name = "TblHosts.findByName", query = "SELECT t FROM TblHosts t WHERE t.name = :name"),
    @NamedQuery(name = "TblHosts.findByIPAddress", query = "SELECT t FROM TblHosts t WHERE t.iPAddress = :iPAddress"),
    @NamedQuery(name = "TblHosts.findByPort", query = "SELECT t FROM TblHosts t WHERE t.port = :port"),
    @NamedQuery(name = "TblHosts.findByDescription", query = "SELECT t FROM TblHosts t WHERE t.description = :description"),
    @NamedQuery(name = "TblHosts.findByAddOnConnectionInfo", query = "SELECT t FROM TblHosts t WHERE t.addOnConnectionInfo = :addOnConnectionInfo"),
    @NamedQuery(name = "TblHosts.findByEmail", query = "SELECT t FROM TblHosts t WHERE t.email = :email"),
    @NamedQuery(name = "TblHosts.findByErrorCode", query = "SELECT t FROM TblHosts t WHERE t.errorCode = :errorCode"),
    @NamedQuery(name = "TblHosts.findByErrorDescription", query = "SELECT t FROM TblHosts t WHERE t.errorDescription = :errorDescription"),
    @NamedQuery(name = "TblHosts.findByNameSearchCriteria", query = "SELECT t FROM TblHosts t WHERE t.name like :search"),
    @NamedQuery(name = "TblHosts.findByHwUUID", query = "SELECT t FROM TblHosts t WHERE t.hardware_uuid = :hardware_uuid"),
    @NamedQuery(name = "TblHosts.findByUuidHex", query = "SELECT t FROM TblHosts t WHERE t.uuid_hex = :uuid_hex")})
public class TblHosts implements Serializable {
    @Transient
    private transient Logger log = LoggerFactory.getLogger(getClass());
    
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "hostId")
    private Collection<TblSamlAssertion> tblSamlAssertionCollection;
    @Column(name = "Location")
    private String location;
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "ID")
    private Integer id;
    @Basic(optional = false)
    @Column(name = "Name")
    private String name;
    @Basic(optional = false)
    @Column(name = "IPAddress")
    private String iPAddress;
    @Basic(optional = false)
    @Column(name = "Port")
    private int port;
    @Column(name = "Description")
    private String description;
    @Column(name = "AddOn_Connection_Info")
    private String addOnConnectionInfo;
    @Lob
    @Column(name = "AIK_Certificate")
    private String aIKCertificate;

    
    @Column(name = "TlsPolicy")
    private String tlsPolicyName;
    
    @Lob
    @Column(name = "TlsKeystore")
    private byte[] tlsKeystore;
    
    @Transient
    private ByteArrayResource tlsKeystoreResource;
    
    @Column(name = "Email")
    private String email;
    @Column(name = "Error_Code")
    private Integer errorCode;
    @Column(name = "Error_Description")
    private String errorDescription;
    @JoinColumn(name = "VMM_MLE_ID", referencedColumnName = "ID")
    @ManyToOne(optional = false)
    private TblMle vmmMleId;
    @JoinColumn(name = "BIOS_MLE_ID", referencedColumnName = "ID")
    @ManyToOne(optional = false)
    private TblMle biosMleId;
    @Column(name = "hardware_uuid")
    private String hardware_uuid;
    @Column(name = "uuid_hex")
    private String uuid_hex;
    @Column(name = "bios_mle_uuid_hex")
    private String bios_mle_uuid_hex;
    @Column(name = "vmm_mle_uuid_hex")
    private String vmm_mle_uuid_hex;
    @Column(name = "AIK_SHA1")
    private String aikSha1;
//    @Column(name = "binding_key_certificate")
//    private String bindingKeyCertificate;
    
    public TblHosts() {
    }

    public TblHosts(Integer id) {
        this.id = id;
    }


    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIPAddress() {
        return iPAddress;
    }

    public void setIPAddress(String iPAddress) {
        this.iPAddress = iPAddress;
    }

    /**
     * XXX TODO the port field is only used for Linux hosts running Trust Agent
     * and needs to be removed;  all agent connection information should be
     * stored in the "AddOn_Connection_String" in a URI format. For Linux hosts
     * with Trust Agent that format might be "intel:https://hostname:9999"
     * @return 
     */
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getAddOnConnectionInfo() {
        return addOnConnectionInfo;
    }

    public void setAddOnConnectionInfo(String addOnConnectionInfo) {
        this.addOnConnectionInfo = addOnConnectionInfo;
    }

    public String getAIKCertificate() {
        return aIKCertificate;
    }

    public void setAIKCertificate(String aIKCertificate) {
        this.aIKCertificate = aIKCertificate;
    }
    
    public String getTlsPolicyName() { return tlsPolicyName; }
    public void setTlsPolicyName(String sslPolicy) { 
        this.tlsPolicyName = sslPolicy; 
    }

    
    public byte[] getTlsKeystore() { 
        return tlsKeystore; 
    }
    public void setTlsKeystore(byte[] tlsKeystoreBytes) {        
        tlsKeystore = tlsKeystoreBytes;
        tlsKeystoreResource = null;
    }

    public Resource getTlsKeystoreResource() { 
        if( tlsKeystoreResource == null ) {
            tlsKeystoreResource = new ByteArrayResource(tlsKeystore) {
                @Override
                protected void onClose() {
                    tlsKeystore = array; // array is a protected member of ByteArrayResource
                }
            };
        }
        return tlsKeystoreResource; 
    }
    
    
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }


    public Integer getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(Integer errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public TblMle getVmmMleId() {
        return vmmMleId;
    }

    public void setVmmMleId(TblMle vmmMleId) {
        this.vmmMleId = vmmMleId;
    }

    public TblMle getBiosMleId() {
        return biosMleId;
    }

    public void setBiosMleId(TblMle biosMleId) {
        this.biosMleId = biosMleId;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof TblHosts)) {
            return false;
        }
        TblHosts other = (TblHosts) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.intel.mountwilson.as.data.TblHosts[ id=" + id + " ]";
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }
    
    public String getHardwareUuid() {
        return hardware_uuid;
    }

    public void setHardwareUuid(String uuid) {
        this.hardware_uuid = uuid;
    }
    
    public String getUuid_hex() {
        return uuid_hex;
    }

    public void setUuid_hex(String uuid_hex) {
        this.uuid_hex = uuid_hex;
    }
    
    public String getBios_mle_uuid_hex() {
        return bios_mle_uuid_hex;
    }

    public void setBios_mle_uuid_hex(String bios_mle_uuid_hex) {
        this.bios_mle_uuid_hex = bios_mle_uuid_hex;
    }
    
    public String getVmm_mle_uuid_hex() {
        return vmm_mle_uuid_hex;
    }

    public void setVmm_mle_uuid_hex(String vmm_mle_uuid_hex) {
        this.vmm_mle_uuid_hex = vmm_mle_uuid_hex;
    }
    
    public String getAikSha1() {
        return aikSha1;
    }
    
    public void setAikSha1(String aikSha1) {
        this.aikSha1 = aikSha1;
    }
    
//    public String getBindingKeyCertificate() {
//        return this.bindingKeyCertificate;
//    }
//
//    public void setBindingKeyCertificate(String bindingKeyCertificate) {
//        this.bindingKeyCertificate = bindingKeyCertificate;
//    }

    @XmlTransient
    public Collection<TblSamlAssertion> getTblSamlAssertionCollection() {
        return this.tblSamlAssertionCollection;
    }

    public void setTblSamlAssertionCollection(Collection<TblSamlAssertion> tblSamlAssertionCollection) {
        this.tblSamlAssertionCollection = tblSamlAssertionCollection;
    }
}
