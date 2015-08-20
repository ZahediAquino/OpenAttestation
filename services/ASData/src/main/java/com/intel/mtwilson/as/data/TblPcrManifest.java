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
import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.xml.bind.annotation.XmlRootElement;
import org.eclipse.persistence.annotations.Customizer;

/**
 *
 * @author dsmagadx
 */
@Entity
@Table(name = "mw_pcr_manifest")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "TblPcrManifest.findAll", query = "SELECT t FROM TblPcrManifest t"),
    @NamedQuery(name = "TblPcrManifest.findById", query = "SELECT t FROM TblPcrManifest t WHERE t.id = :id"),
    @NamedQuery(name = "TblPcrManifest.findByName", query = "SELECT t FROM TblPcrManifest t WHERE t.name = :name"),
    @NamedQuery(name = "TblPcrManifest.findByValue", query = "SELECT t FROM TblPcrManifest t WHERE t.value = :value"),
//    @NamedQuery(name = "TblPcrManifest.findByCreatedOn", query = "SELECT t FROM TblPcrManifest t WHERE t.createdOn = :createdOn"),
//    @NamedQuery(name = "TblPcrManifest.findByUpdatedOn", query = "SELECT t FROM TblPcrManifest t WHERE t.updatedOn = :updatedOn"),
    @NamedQuery(name = "TblPcrManifest.findByPCRDescription", query = "SELECT t FROM TblPcrManifest t WHERE t.pCRDescription = :pCRDescription"),
    @NamedQuery(name = "TblPcrManifest.findByMleIdName", query = "SELECT t FROM TblPcrManifest t WHERE t.mleId.id = :mleId and t.name = :name")})

public class TblPcrManifest implements Serializable {
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
    @Column(name = "Value")
    private String value;
    @Column(name = "PCR_Description")
    private String pCRDescription;
    @Column(name = "uuid_hex")
    private String uuid_hex;
    @Column(name = "mle_uuid_hex")
    private String mle_uuid_hex;
    
    @JoinColumn(name = "MLE_ID", referencedColumnName = "ID")
    @ManyToOne(optional = false)
    private TblMle mleId;

    public TblPcrManifest() {
    }

    public TblPcrManifest(Integer id) {
        this.id = id;
    }

    public TblPcrManifest(Integer id, String name, String value, Date createdOn, Date updatedOn) {
        this.id = id;
        this.name = name;
        this.value = value;
    }

    public TblPcrManifest(Integer id, String name, String value) {
        this.id = id;
        this.name = name;
        this.value = value;
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

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getPCRDescription() {
        return pCRDescription;
    }

    public void setPCRDescription(String pCRDescription) {
        this.pCRDescription = pCRDescription;
    }
    
    public String getUuid_hex() {
        return uuid_hex;
    }

    public void setUuid_hex(String uuid_hex) {
        this.uuid_hex = uuid_hex;
    }

    public String getMle_uuid_hex() {
        return mle_uuid_hex;
    }

    public void setMle_uuid_hex(String mle_uuid_hex) {
        this.mle_uuid_hex = mle_uuid_hex;
    }


    public TblMle getMleId() {
        return mleId;
    }

    public void setMleId(TblMle mleId) {
        this.mleId = mleId;
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
        if (!(object instanceof TblPcrManifest)) {
            return false;
        }
        TblPcrManifest other = (TblPcrManifest) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.intel.mountwilson.as.data.TblPcrManifest[ id=" + id + " ]";
    }
    
}
