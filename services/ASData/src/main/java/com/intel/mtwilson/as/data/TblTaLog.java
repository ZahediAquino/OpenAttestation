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
import java.util.Date;
import javax.persistence.*;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import org.eclipse.persistence.annotations.Customizer;

/**
 *
 * @author dsmagadx
 */
@Entity
@Table(name = "mw_ta_log")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "TblTaLog.findAll", query = "SELECT t FROM TblTaLog t"),
    @NamedQuery(name = "TblTaLog.findById", query = "SELECT t FROM TblTaLog t WHERE t.id = :id"),
    @NamedQuery(name = "TblTaLog.findTrustStatusByHostId", query = "SELECT t FROM TblTaLog t WHERE t.hostID = :hostID and t.mleId = 0 order by t.updatedOn desc"),
    @NamedQuery(name = "TblTaLog.findLogsByHostId", query = "SELECT t FROM TblTaLog t WHERE t.hostID = :hostID and t.mleId <> 0 and t.updatedOn = :updatedOn"),
    @NamedQuery(name = "TblTaLog.findLogsByHostId2", query = "SELECT t FROM TblTaLog t WHERE t.hostID = :hostID"),
    @NamedQuery(name = "TblTaLog.findLastStatusTs", query = "SELECT t FROM TblTaLog t WHERE t.hostID = :hostID order by t.updatedOn desc"),
    @NamedQuery(name = "TblTaLog.findByMleId", query = "SELECT t FROM TblTaLog t WHERE t.mleId = :mleId"),
    @NamedQuery(name = "TblTaLog.findByManifestName", query = "SELECT t FROM TblTaLog t WHERE t.manifestName = :manifestName"),
    @NamedQuery(name = "TblTaLog.findByManifestValue", query = "SELECT t FROM TblTaLog t WHERE t.manifestValue = :manifestValue"),
    @NamedQuery(name = "TblTaLog.findByTrustStatus", query = "SELECT t FROM TblTaLog t WHERE t.trustStatus = :trustStatus"),
    @NamedQuery(name = "TblTaLog.findByError", query = "SELECT t FROM TblTaLog t WHERE t.error = :error"),
    @NamedQuery(name = "TblTaLog.findByUpdatedOn", query = "SELECT t FROM TblTaLog t WHERE t.updatedOn = :updatedOn"),
    @NamedQuery(name = "TblTaLog.getHostTALogEntryBefore", query = "SELECT t FROM TblTaLog t WHERE t.hostID = :hostId and t.updatedOn > :expiryTs and t.mleId = 0 ORDER BY t.updatedOn DESC")
})

public class TblTaLog implements Serializable {
    @Basic(optional = false)
    @Column(name = "Updated_On")
    @Temporal(TemporalType.TIMESTAMP)
    private Date updatedOn;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "taLogId")
    private Collection<TblModuleManifestLog> tblModuleManifestLogCollection;
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "ID")
    private Integer id;
    @Basic(optional = false)
    @Column(name = "Host_ID")
    private int hostID;
    @Basic(optional = false)
    @Column(name = "MLE_ID")
    private int mleId;
    @Basic(optional = false)
    @Column(name = "Manifest_Name")
    private String manifestName;
    @Basic(optional = false)
    @Column(name = "Manifest_Value")
    private String manifestValue;
    @Basic(optional = false)
    @Column(name = "Trust_Status")
    private boolean trustStatus;
    @Column(name = "Error")
    private String error;
    @Column(name = "uuid_hex")
    private String uuid_hex;
    @Column(name = "mle_uuid_hex")
    private String mle_uuid_hex;

    public TblTaLog() {
    }

    public TblTaLog(Integer id) {
        this.id = id;
    }

    public TblTaLog(Integer id, int hostID, int mleId, String manifestName, String manifestValue, boolean trustStatus, Date updatedOn) {
        this.id = id;
        this.hostID = hostID;
        this.mleId = mleId;
        this.manifestName = manifestName;
        this.manifestValue = manifestValue;
        this.trustStatus = trustStatus;
        this.updatedOn = updatedOn;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public int getHostID() {
        return hostID;
    }

    public void setHostID(int hostID) {
        this.hostID = hostID;
    }

    public int getMleId() {
        return mleId;
    }

    public void setMleId(int mleId) {
        this.mleId = mleId;
    }

    public String getManifestName() {
        return manifestName;
    }

    public void setManifestName(String manifestName) {
        this.manifestName = manifestName;
    }

    public String getManifestValue() {
        return manifestValue;
    }

    public void setManifestValue(String manifestValue) {
        this.manifestValue = manifestValue;
    }

    public boolean getTrustStatus() {
        return trustStatus;
    }

    public void setTrustStatus(boolean trustStatus) {
        this.trustStatus = trustStatus;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public Date getUpdatedOn() {
        return updatedOn;
    }

    public void setUpdatedOn(Date updatedOn) {
        this.updatedOn = updatedOn;
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
  

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof TblTaLog)) {
            return false;
        }
        TblTaLog other = (TblTaLog) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.intel.mountwilson.as.data.TblTaLog[ id=" + id + " ]";
    }


    @XmlTransient
    public Collection<TblModuleManifestLog> getTblModuleManifestLogCollection() {
        return tblModuleManifestLogCollection;
    }

    public void setTblModuleManifestLogCollection(Collection<TblModuleManifestLog> tblModuleManifestLogCollection) {
        this.tblModuleManifestLogCollection = tblModuleManifestLogCollection;
    }
    
}
