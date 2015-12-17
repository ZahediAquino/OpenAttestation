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
import com.intel.mtwilson.as.data.TblHosts;
import java.io.Serializable;
import javax.persistence.Query;
import javax.persistence.EntityNotFoundException;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import com.intel.mtwilson.as.data.TblMle;
import com.intel.mtwilson.crypto.CryptographyException;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dsmagadX
 */
public class TblHostsJpaController implements Serializable {
    private Logger log = LoggerFactory.getLogger(getClass());

    private EntityManagerFactory emf = null;

    public TblHostsJpaController(EntityManagerFactory emf) throws CryptographyException {
        this.emf = emf;
    }

    public TblHostsJpaController(EntityManagerFactory emf, boolean isTest) {
        this.emf = emf;
    }
    
    public EntityManager getEntityManager() {
        return emf.createEntityManager();
    }

    public void create(TblHosts tblHosts) throws CryptographyException {
        log.debug("create tblHosts with policy {} and keystore length {}", tblHosts.getTlsPolicyName(), tblHosts.getTlsKeystore() == null ? "null" : tblHosts.getTlsKeystore().length);
        EntityManager em = getEntityManager();
        try {
            em.getTransaction().begin();
            TblMle vmmMleId = tblHosts.getVmmMleId();
            if (vmmMleId != null) {
                vmmMleId = em.getReference(vmmMleId.getClass(), vmmMleId.getId());
                tblHosts.setVmmMleId(vmmMleId);
            }
            TblMle biosMleId = tblHosts.getBiosMleId();
            if (biosMleId != null) {
                biosMleId = em.getReference(biosMleId.getClass(), biosMleId.getId());
                tblHosts.setBiosMleId(biosMleId);
            }
            
            // encrypt addon connection string, persist, then restore the plaintext
            String addOnConnectionString = tblHosts.getAddOnConnectionInfo();
            if( addOnConnectionString != null ) {
                em.persist(tblHosts);
            }
            else {
                log.debug("saving without encrypting connection string");
                em.persist(tblHosts);
            }
            
            if (vmmMleId != null) {
                vmmMleId.getTblHostsCollection().add(tblHosts);
                em.merge(vmmMleId);
            }
            if (biosMleId != null) {
                biosMleId.getTblHostsCollection().add(tblHosts);
                em.merge(biosMleId);
            }
            em.getTransaction().commit();
        } finally {
            em.close();
        }
    }

    public void edit(TblHosts tblHosts) throws IllegalOrphanException, NonexistentEntityException, ASDataException {
        EntityManager em = getEntityManager();
        try {
            em.getTransaction().begin();
            TblHosts persistentTblHosts = em.find(TblHosts.class, tblHosts.getId());
            TblMle vmmMleIdOld = persistentTblHosts.getVmmMleId();
            TblMle vmmMleIdNew = tblHosts.getVmmMleId();
            TblMle biosMleIdOld = persistentTblHosts.getBiosMleId();
            TblMle biosMleIdNew = tblHosts.getBiosMleId();
            if (vmmMleIdNew != null) {
                vmmMleIdNew = em.getReference(vmmMleIdNew.getClass(), vmmMleIdNew.getId());
                tblHosts.setVmmMleId(vmmMleIdNew);
            }
            if (biosMleIdNew != null) {
                biosMleIdNew = em.getReference(biosMleIdNew.getClass(), biosMleIdNew.getId());
                tblHosts.setBiosMleId(biosMleIdNew);
            }

            // encrypt addon connection string, persist, then restore the plaintext
            String addOnConnectionString = tblHosts.getAddOnConnectionInfo();
            if( addOnConnectionString != null ) {
                tblHosts = em.merge(tblHosts);
            }
            else {
                tblHosts = em.merge(tblHosts);
            }
            
            if (vmmMleIdOld != null && !vmmMleIdOld.equals(vmmMleIdNew)) {
                vmmMleIdOld.getTblHostsCollection().remove(tblHosts);
                vmmMleIdOld = em.merge(vmmMleIdOld);
            }
            if (vmmMleIdNew != null && !vmmMleIdNew.equals(vmmMleIdOld)) {
                vmmMleIdNew.getTblHostsCollection().add(tblHosts);
                em.merge(vmmMleIdNew);
            }
            if (biosMleIdOld != null && !biosMleIdOld.equals(biosMleIdNew)) {
                biosMleIdOld.getTblHostsCollection().remove(tblHosts);
                biosMleIdOld = em.merge(biosMleIdOld);
            }
            if (biosMleIdNew != null && !biosMleIdNew.equals(biosMleIdOld)) {
                biosMleIdNew.getTblHostsCollection().add(tblHosts);
                em.merge(biosMleIdNew);
            }
            em.getTransaction().commit();
        } catch (Exception ex) {
            String msg = ex.getLocalizedMessage();
            if (msg == null || msg.length() == 0) {
                Integer id = tblHosts.getId();
                if (findTblHosts(id) == null) {
                    throw new NonexistentEntityException("The tblHosts with id " + id + " no longer exists.");
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
            TblHosts tblHosts;
            try {
                tblHosts = em.getReference(TblHosts.class, id);
                tblHosts.getId();
            } catch (EntityNotFoundException enfe) {
                throw new NonexistentEntityException("The tblHosts with id " + id + " no longer exists.", enfe);
            }
            TblMle vmmMleId = tblHosts.getVmmMleId();
            if (vmmMleId != null) {
                vmmMleId.getTblHostsCollection().remove(tblHosts);
                em.merge(vmmMleId);
            }
            TblMle biosMleId = tblHosts.getBiosMleId();
            if (biosMleId != null) {
                biosMleId.getTblHostsCollection().remove(tblHosts);
                em.merge(biosMleId);
            }
            em.remove(tblHosts);
            em.getTransaction().commit();
        } finally {
            em.close();
        }
    }
    
    public List<TblHosts> findTblHostsEntities() {
        return findTblHostsEntities(true, -1, -1);
    }

    public List<TblHosts> findTblHostsEntities(int maxResults, int firstResult) {
        return findTblHostsEntities(false, maxResults, firstResult);
    }

    private List<TblHosts> findTblHostsEntities(boolean all, int maxResults, int firstResult) {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            cq.select(cq.from(TblHosts.class));
            Query q = em.createQuery(cq);
            if (!all) {
                q.setMaxResults(maxResults);
                q.setFirstResult(firstResult);
            }
            List<TblHosts> results = q.getResultList();
            return results;
        } finally {
            em.close();
        }
    }

    public TblHosts findTblHosts(Integer id) {
        EntityManager em = getEntityManager();
        try {
            TblHosts result = em.find(TblHosts.class, id);
            return result;
        } finally {
            em.close();
        }
    }

    public int getTblHostsCount() {
        EntityManager em = getEntityManager();
        try {
            CriteriaQuery cq = em.getCriteriaBuilder().createQuery();
            Root<TblHosts> rt = cq.from(TblHosts.class);
            cq.select(em.getCriteriaBuilder().count(rt));
            Query q = em.createQuery(cq);
            return ((Long) q.getSingleResult()).intValue();
        } finally {
            em.close();
        }
    }

    public TblHosts findByName(String name) {

        TblHosts host = null;
        EntityManager em = getEntityManager();
        try {

            Query query = em.createNamedQuery("TblHosts.findByName");

            query.setParameter("name", name);
          

            List<TblHosts> list = query.getResultList();

            if (list != null && list.size() > 0) {
                host = list.get(0);
            }
        } finally {
                em.close();
        }

        return host;

    }

      public TblHosts findByIPAddress(String ipAddress) {

        TblHosts host = null;
        EntityManager em = getEntityManager();
        try {
            Query query = em.createNamedQuery("TblHosts.findByIPAddress");

            query.setParameter("iPAddress", ipAddress);
          

            List<TblHosts> list = query.getResultList();

            if (list != null && list.size() > 0) {
                host = list.get(0);
            }
        } finally {
                em.close();
        }

        return host;

    }
    
    public List<TblHosts> findHostsByNameSearchCriteria(String searchCriteria) {
        List<TblHosts> hostList = null;
        EntityManager em = getEntityManager();
        
        try {           
            Query query = em.createNamedQuery("TblHosts.findByNameSearchCriteria");
            query.setParameter("search", "%"+searchCriteria+"%");
            
            if (query.getResultList() != null && !query.getResultList().isEmpty()) {
                 
                hostList = query.getResultList();
            }
            
        } finally {
            em.close();
        }
        
        return hostList;      
    }
	
	public TblHosts findByHwUUID(String hardware_uuid) {

        TblHosts host = null;
        EntityManager em = getEntityManager();
        try {

            Query query = em.createNamedQuery("TblHosts.findByHwUUID");

            query.setParameter("hardware_uuid", hardware_uuid);
          

            List<TblHosts> list = query.getResultList();

            if (list != null && list.size() > 0) {
                host = list.get(0);
               
            }
        } finally {
                em.close();
        }

        return host;

    }

}
