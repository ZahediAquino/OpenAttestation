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

package com.intel.mountwilson.manifest.data;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.logging.Logger;

import com.intel.mountwilson.as.common.ASException;
import com.intel.mountwilson.manifest.helper.SHA1HashBuilder;
import com.intel.mtwilson.datatypes.ErrorCode;
import java.util.ArrayList;
import java.util.List;

/**
 * XXX the interface needs to change, see comments on IManifest
 */
public class PcrModuleManifest extends PcrManifest implements IManifest {
	Logger log = Logger.getLogger(getClass().getName());
	
	private SHA1HashBuilder builder = new SHA1HashBuilder();
	
	public PcrModuleManifest(int pcrNumber, String pcrValue) {
		super(pcrNumber, pcrValue);

	}

        /**
         * XXX TODO WARNING currently this code allows a host to have a SUBSET of the modules defined in the whitelist and still be trusted... that's not correct, because one of the modules not in the subset could be an important auditing or security module. 
         * @param goodKnownValue
         * @return 
         */
	@Override
	public boolean verify(IManifest goodKnownValue) {
		boolean isTrusted = true;
		
		if( goodKnownValue instanceof PcrModuleManifest && (((PcrManifest) goodKnownValue).getPcrValue() == null
				|| ((PcrManifest) goodKnownValue).getPcrValue().isEmpty() )){

			log.info(String.format("PCR [%s] Digest value [%s] - Computed digest [%s]",String.valueOf(getPcrNumber()),getPcrValue(),getComputedDigest()));
			if(!getPcrValue().equalsIgnoreCase(getComputedDigest()) && isTrusted){
				log.info(String.format("PCR [%s] Digest value  and Computed digest does not match",getPcrValue()));
				isTrusted = false;
			}
			
		}else{
			if( !super.verify(goodKnownValue))
				isTrusted = false;
		}
			

		
		verifyStatus = isTrusted;
		
		log.info( String.format("Returing verify status [%s] for pcr [%d]", String.valueOf( verifyStatus),getPcrNumber()));
		
		return isTrusted;
	}

	public void appendDigest(byte[] dataToAppend){
		
		builder.append(dataToAppend);
	}


	
	public String getComputedDigest(){
		
		String digest = byteArrayToHexString(builder.get_data());
		return digest;
	}

	protected String byteArrayToHexString(byte[] bytes) {
		BigInteger bi = new BigInteger(1, bytes);
	    return String.format("%0" + (bytes.length << 1) + "X", bi);
	}

	

}
