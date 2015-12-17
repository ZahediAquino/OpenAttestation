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

import java.io.Serializable;
import java.util.Collection;
import javax.persistence.Basic;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import org.eclipse.persistence.annotations.Customizer;

/**
 *
 * @author dsmagadx
 */
@Entity
@Table(name = "mw_mle")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "TblMle.findAll", query = "SELECT t FROM TblMle t"),
    @NamedQuery(name = "TblMle.findById", query = "SELECT t FROM TblMle t WHERE t.id = :id"),
    @NamedQuery(name = "TblMle.findByName", query = "SELECT t FROM TblMle t WHERE t.name = :name"),
    @NamedQuery(name = "TblMle.findByVersion", query = "SELECT t FROM TblMle t WHERE t.version = :version"),
    @NamedQuery(name = "TblMle.findByAttestationType", query = "SELECT t FROM TblMle t WHERE t.attestationType = :attestationType"),
    @NamedQuery(name = "TblMle.findByMLEType", query = "SELECT t FROM TblMle t WHERE t.mLEType = :mLEType"),
    @NamedQuery(name = "TblMle.findByRequiredManifestList", query = "SELECT t FROM TblMle t WHERE t.requiredManifestList = :requiredManifestList"),
    @NamedQuery(name = "TblMle.findByDescription", query = "SELECT t FROM TblMle t WHERE t.description = :description"),
    @NamedQuery(name = "TblMle.findByNameAndVersion", query = "SELECT t FROM TblMle t WHERE t.name = :name and t.version = :version and t.mLEType = :mletype"),
    @NamedQuery(name = "TblMle.findByNameAndVersionNoType", query = "SELECT t FROM TblMle t WHERE t.name = :name and t.version = :version"),
    @NamedQuery(name = "TblMle.findBiosMle", query = "SELECT t FROM TblMle t WHERE t.name = :name and t.version = :version and t.oemId.name = :oemName"),
    @NamedQuery(name = "TblMle.findVmmMle", query = "SELECT t FROM TblMle t WHERE t.name = :name and t.version = :version and t.osId.name = :osName and t.osId.version =:osVersion"),
    @NamedQuery(name = "TblMle.findVmmMleByNameSearchCriteria", query = "SELECT t FROM TblMle t WHERE t.name like :search or t.osId.name like :search"),
    @NamedQuery(name = "TblMle.findBiosMleByNameSearchCriteria", query = "SELECT t FROM TblMle t WHERE t.name like :search or t.oemId.name like :search"),
    @NamedQuery(name = "TblMle.findByUUID_Hex", query = "SELECT t FROM TblMle t WHERE t.uuid_hex = :uuid_hex")})
//
public class TblMle implements Serializable {

    @JoinColumn(name = "OEM_ID", referencedColumnName = "ID")
    @ManyToOne
    private TblOem oemId;
    @JoinColumn(name = "OS_ID", referencedColumnName = "ID")
    @ManyToOne
    private TblOs osId;
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
    @Column(name = "Version")
    private String version;
    @Basic(optional = false)
    @Column(name = "Attestation_Type")
    private String attestationType;
    @Basic(optional = false)
    @Column(name = "MLE_Type")
    private String mLEType;
    @Basic(optional = false)
    @Column(name = "Required_Manifest_List")
    private String requiredManifestList;
    @Column(name = "Description")
    private String description;
    @Column(name = "uuid_hex")
    private String uuid_hex;
    @Column(name = "oem_uuid_hex")
    private String oem_uuid_hex;
    @Column(name = "os_uuid_hex")
    private String os_uuid_hex;
    
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "vmmMleId")
    private Collection<TblHosts> tblHostsCollection;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "biosMleId")
    private Collection<TblHosts> tblHostsCollection1;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "mleId")
    private Collection<TblPcrManifest> tblPcrManifestCollection;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "mleId")
    private Collection<TblModuleManifest> tblModuleManifestCollection;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "mleId")
    private Collection<MwMleSource> mwMleSourceCollection;
    
    public TblMle() {
    }

    public TblMle(Integer id) {
        this.id = id;
    }

    public TblMle(Integer id, String name, String version, String attestationType, String mLEType, String requiredManifestList) {
        this.id = id;
        this.name = name;
        this.version = version;
        this.attestationType = attestationType;
        this.mLEType = mLEType;
        this.requiredManifestList = requiredManifestList;
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

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getAttestationType() {
        return attestationType;
    }

    public void setAttestationType(String attestationType) {
        this.attestationType = attestationType;
    }

    public String getMLEType() {
        return mLEType;
    }

    public void setMLEType(String mLEType) {
        this.mLEType = mLEType;
    }

    public String getRequiredManifestList() {
        return requiredManifestList;
    }

    public void setRequiredManifestList(String requiredManifestList) {
        this.requiredManifestList = requiredManifestList;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
    
    public String getUuid_hex() {
        return uuid_hex;
    }

    public void setUuid_hex(String uuid_hex) {
        this.uuid_hex = uuid_hex;
    }
    
    public String getOem_uuid_hex() {
        return oem_uuid_hex;
    }

    public void setOem_uuid_hex(String oem_uuid_hex) {
        this.oem_uuid_hex = oem_uuid_hex;
    }
    
    public String getOs_uuid_hex() {
        return os_uuid_hex;
    }

    public void setOs_uuid_hex(String os_uuid_hex) {
        this.os_uuid_hex = os_uuid_hex;
    }

    @XmlTransient
    public Collection<TblHosts> getTblHostsCollection() {
        return tblHostsCollection;
    }

    public void setTblHostsCollection(Collection<TblHosts> tblHostsCollection) {
        this.tblHostsCollection = tblHostsCollection;
    }

    @XmlTransient
    public Collection<TblHosts> getTblHostsCollection1() {
        return tblHostsCollection1;
    }

    public void setTblHostsCollection1(Collection<TblHosts> tblHostsCollection1) {
        this.tblHostsCollection1 = tblHostsCollection1;
    }

    @XmlTransient
    public Collection<TblPcrManifest> getTblPcrManifestCollection() {
        return tblPcrManifestCollection;
    }

    public void setTblPcrManifestCollection(Collection<TblPcrManifest> tblPcrManifestCollection) {
        this.tblPcrManifestCollection = tblPcrManifestCollection;
    }

    @XmlTransient
    public Collection<TblModuleManifest> getTblModuleManifestCollection() {
        return tblModuleManifestCollection;
    }

    public void setTblModuleManifestCollection(Collection<TblModuleManifest> tblModuleManifestCollection) {
        this.tblModuleManifestCollection = tblModuleManifestCollection;
    }

    @XmlTransient
    public Collection<MwMleSource> getMwMleSourceCollection() {
        return mwMleSourceCollection;
    }

    public void setMwMleSourceCollection(Collection<MwMleSource> mwMleSourceCollection) {
        this.mwMleSourceCollection = mwMleSourceCollection;
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
        if (!(object instanceof TblMle)) {
            return false;
        }
        TblMle other = (TblMle) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.intel.mountwilson.as.data.TblMle[ id=" + id + " ]";
    }

    public TblOem getOemId() {
        return oemId;
    }

    public void setOemId(TblOem oemId) {
        this.oemId = oemId;
    }

    public TblOs getOsId() {
        return osId;
    }

    public void setOsId(TblOs osId) {
        this.osId = osId;
    }
}
