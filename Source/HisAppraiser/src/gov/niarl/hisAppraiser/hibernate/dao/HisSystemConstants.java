/*
 * (copyright) 2012 United States Government, as represented by the 
 * Secretary of Defense.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 * 
 * - Redistributions of source code must retain the above copyright 
 * notice, this list of conditions and the following disclaimer. 
 * 
 * - Redistributions in binary form must reproduce the above copyright 
 * notice, this list of conditions and the following disclaimer in the 
 * documentation and/or other materials provided with the distribution. 
 * 
 * - Neither the name of the U.S. Government nor the names of its 
 * contributors may be used to endorse or promote products derived from 
 * this software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE. 
 */
package gov.niarl.hisAppraiser.hibernate.dao;

import gov.niarl.hisAppraiser.hibernate.domain.SystemConstants;
import gov.niarl.hisAppraiser.hibernate.util.HibernateUtilHis;

import java.util.HashMap;
import java.util.List;

import org.hibernate.Query;

/**
 * This class serves as a central location for updates and queries against 
 * the SystemConstants table.
 * @author syelama
 * @version Crossbow
 *
 */
public class HisSystemConstants {

	private static HashMap<String, String> HASH_MAP = getSystemConstants();

	/**
	 * The delay linked to the 
	 */
	public static final long DEFAULT_DELAY = Long.parseLong(getSystemConstants().get("default_delay"));

	static {
		HASH_MAP = null;
	}

	/**
	 * Generate a hash map from the SystemConstants table.
	 * @return Hash map of the SystemConstants table.
	 */
	private static synchronized HashMap<String, String> getSystemConstants() {
		HashMap<String, String> hashMap = new HashMap<String, String>();
		try {
			HibernateUtilHis.beginTransaction();

			Query query = HibernateUtilHis.getSession().createQuery("from SystemConstants");
			List<SystemConstants> list = query.list();
			for (SystemConstants systemConstants : list) {
				hashMap.put(systemConstants.getKeyId(), systemConstants.getValue());
			}

			HibernateUtilHis.commitTransaction();
		} catch (Exception e) {
			HibernateUtilHis.rollbackTransaction();
			e.printStackTrace();
			throw new RuntimeException(e.toString());
		} finally {
			HibernateUtilHis.closeSession();
		}
		return hashMap;
	}
}