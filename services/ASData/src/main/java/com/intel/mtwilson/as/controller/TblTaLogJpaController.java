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
package com.intel.mtwilson.as.controller;

import com.intel.mtwilson.as.controller.exceptions.ASDataException;
import com.intel.mtwilson.as.controller.exceptions.IllegalOrphanException;
import com.intel.mtwilson.as.controller.exceptions.NonexistentEntityException;
import java.io.Serializable;
import javax.persistence.Query;
import javax.persistence.EntityNotFoundException;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import com.intel.mtwilson.as.data.TblTaLog;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author dsmagadx
 */
public class TblTaLogJpaController implements Serializable {
    
    private Logger log = LoggerFactory.getLogger(getClass());
    
    public TblTaLogJpaController( EntityManagerFactory emf) {
        this.emf = emf;
    }
    private EntityManagerFactory emf = null;

    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(TblTaLog tblTaLog) {
        EntityManager em = getEntityManager();
        try {
            em.getTransaction().begin();
            em.persist(tblTaLog);
            em.getTransaction().commit();
        } finally {
                em.close();
        }
    }

    public void edit(TblTaLog tblTaLog) throws IllegalOrphanException, NonexistentEntityException, ASDataException {
        EntityManager em = getEntityManager();
        try {
            em.getTransaction().begin();
            // commenting out unused variable for klocwork scans
            // stdalex 3/4
            //TblTaLog persistentTblTaLog = em.find(TblTaLog.class, tblTaLog.getId());
            em.merge(tblTaLog);
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                Integer id = tblTaLog.getId();
                if (findTblTaLog(id) == null) {
                    throw new NonexistentEntityException("The tblTaLog with id " + id + " no longer exists.");
                }
            }
            throw new ASDataException(ex);
        } finally {
                em.close();
        }
    }

    public void destroy(Integer id) throws IllegalOrphanException, NonexistentEntityException {
        EntityManager em = getEntityManager();
        try {
            em.getTransaction().begin();
            TblTaLog tblTaLog;
            try {
                tblTaLog = em.getReference(TblTaLog.class, id);
                tblTaLog.getId();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The tblTaLog with id " + id + " no longer exists.", enfe);
            }
            em.remove(tblTaLog);
            em.getTransaction().commit();
        } finally {
                em.close();
        }
    }

    public List<TblTaLog> findTblTaLogEntities() {
        return findTblTaLogEntities(true, -1, -1);
    }

    public List<TblTaLog> findTblTaLogEntities(int maxResults, int firstResult) {
        return findTblTaLogEntities(false, maxResults, firstResult);
    }

    private List<TblTaLog> findTblTaLogEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(TblTaLog.class));
            Query q = em.createQuery(cq);
            if (!all) {
                q.setMaxResults(maxResults);
                q.setFirstResult(firstResult);
            }
            return q.getResultList();
        } finally {
            em.close();
        }
    }

    public TblTaLog findTblTaLog(Integer id) {
        EntityManager em = getEntityManager();
        try {
            return em.find(TblTaLog.class, id);
        } finally {
            em.close();
        }
    }

    public int getTblTaLogCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<TblTaLog> rt = cq.from(TblTaLog.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }
    // Custom find methods
    
        
    public List<TblTaLog> findTrustStatusByHostId(int hostId, int maxresults  ){        
        EntityManager em = getEntityManager();
        try {

            Query query = em.createNamedQuery("TblTaLog.findTrustStatusByHostId");

            query.setParameter("hostID", hostId);
            query.setMaxResults(maxresults);

            List<TblTaLog> logs = query.getResultList();
            
            return logs;

        } finally {
            em.close();
        }
    }

    
     public List<TblTaLog> findLogsByHostId(int hostId , Date lastUpdatedTs ){
        
        EntityManager em = getEntityManager();
        try {
            Query query = em.createNamedQuery("TblTaLog.findLogsByHostId");
            
            query.setParameter("hostID", hostId);
            query.setParameter("updatedOn", lastUpdatedTs);
            
            List<TblTaLog> logs = query.getResultList();
            return logs;
            
        } finally {
            em.close();
        }
    }

    public Date findLastStatusTs(Integer hostId) {
        Date lastUpdateTs = null;
        EntityManager em = getEntityManager();
        try {
            Query query = em.createNamedQuery("TblTaLog.findLastStatusTs");
            query.setParameter("hostID", hostId);
            query.setMaxResults(1);
            List<TblTaLog> logs = query.getResultList();
            if(logs != null && logs.size() == 1)
                lastUpdateTs = logs.get(0).getUpdatedOn();
            
        } finally {
            em.close();
        }
        return lastUpdateTs;
    }

    public List<TblTaLog> findLogsByHostId(int hostId ){
        
        EntityManager em = getEntityManager();
        try {
            Query query = em.createNamedQuery("TblTaLog.findLogsByHostId2");
            query.setParameter("hostID", hostId);
            
            List<TblTaLog> logs = query.getResultList();
            return logs;
            
        } finally {
            em.close();
        }
    }
    
    public TblTaLog getHostTALogEntryBefore(int hostId, Date expiryTime) {

        EntityManager em = getEntityManager();
        try {
            Query query = em.createNamedQuery("TblTaLog.getHostTALogEntryBefore");
            query.setParameter("hostId", hostId);
            query.setParameter("expiryTs", expiryTime);
            
            List<TblTaLog> logs = query.getResultList();
            if(logs != null && logs.size() > 0) {
                return logs.get(0);
            }
            
        } finally {
            em.close();
        }
        return null;
    }


}
