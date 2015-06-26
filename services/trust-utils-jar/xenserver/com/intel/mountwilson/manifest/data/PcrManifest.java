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

import java.util.logging.Logger;


/**
 * BUG #497 needs to be rewritten as Pcr ;  the verify() method is nothing
 * more than equals() and it only checks the VALUE ,it does not make sure that
 * the value is in the SAME REGISTER NUMBER, which is important.
 * XXX the interface needs to change, see comments on IManifest
 */
public class PcrManifest implements IManifest {
	Logger log = Logger.getLogger(getClass().getName());
	public PcrManifest(int pcrNumber, String pcrValue) {
		super();
		this.pcrNumber = pcrNumber;
		this.pcrValue = pcrValue;
	}

	private int pcrNumber;
	private String pcrValue;
	protected boolean verifyStatus = false;
	
	
	public int getPcrNumber() {
		return pcrNumber;
	}

	public void setPcrNumber(int pcrNumber) {
		this.pcrNumber = pcrNumber;
	}

	public String getPcrValue() {
		return pcrValue;
	}

	public void setPcrValue(String pcrValue) {
		this.pcrValue = pcrValue;
	}

	@Override
	public boolean verify(IManifest gkv) {

		PcrManifest goodKnownValue = (PcrManifest) gkv;
		
		log.info(String.format("GKV PCR [%d] value [%s] and manifest pcr value [%s]",getPcrNumber(),goodKnownValue.getPcrValue(),getPcrValue() ));
		
//		// TODO: need to check what to do with this case
//		if(goodKnownValue.getPcrValue() == null || goodKnownValue.getPcrValue().isEmpty()){
//			verifyStatus = true;
//		}
		
		
		if ( goodKnownValue.getPcrValue().equalsIgnoreCase(this.pcrValue)) {
			verifyStatus = true;
		}
		return verifyStatus;
	}

	public boolean getVerifyStatus() {
		return verifyStatus;
	}

}
