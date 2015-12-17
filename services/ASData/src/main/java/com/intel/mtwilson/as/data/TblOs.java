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
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
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
@Table(name = "mw_os")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "TblOs.findAll", query = "SELECT t FROM TblOs t"),
    @NamedQuery(name = "TblOs.findById", query = "SELECT t FROM TblOs t WHERE t.id = :id"),
    @NamedQuery(name = "TblOs.findByName", query = "SELECT t FROM TblOs t WHERE t.name = :name"),
    @NamedQuery(name = "TblOs.findByVersion", query = "SELECT t FROM TblOs t WHERE t.version = :version"),
    @NamedQuery(name = "TblOs.findByDescription", query = "SELECT t FROM TblOs t WHERE t.description = :description"),
    @NamedQuery(name = "TblOs.findByNameLike", query = "SELECT t FROM TblOs t WHERE t.name LIKE :name"), // it's the caller's responsibility to add "%" before and/or after the name value    
    @NamedQuery(name = "TblOs.findByUUID_Hex", query = "SELECT t FROM TblOs t WHERE t.uuid_hex = :uuid_hex"),    
    @NamedQuery(name = "TblOs.findTblOsByNameVersion", query = "SELECT t FROM TblOs t WHERE t.name= :name and t.version = :version")})
//
public class TblOs implements Serializable {
    @OneToMany(mappedBy = "osId")
    private Collection<TblMle> tblMleCollection;

    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "ID")
    private Integer id;
    @Basic(optional = false)
    @Column(name = "NAME")
    private String name;
    @Basic(optional = false)
    @Column(name = "VERSION")
    private String version;
    @Column(name = "DESCRIPTION")
    private String description;    
    @Column(name = "uuid_hex")
    private String uuid_hex;

    public TblOs() {
    }

    public TblOs(Integer id) {
        this.id = id;
    }

    public TblOs(Integer id, String name, String version) {
        this.id = id;
        this.name = name;
        this.version = version;
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

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof TblOs)) {
            return false;
        }
        TblOs other = (TblOs) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.intel.mountwilson.as.data.TblOs[ id=" + id + " ]";
    }

    @XmlTransient
    public Collection<TblMle> getTblMleCollection() {
        return tblMleCollection;
    }

    public void setTblMleCollection(Collection<TblMle> tblMleCollection) {
        this.tblMleCollection = tblMleCollection;
    }
}
