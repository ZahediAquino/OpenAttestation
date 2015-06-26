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

package com.intel.mountwilson.manifest.helper;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.datatypes.ErrorCode;

/**
 * XXX this class is intended to model hash-extending but does not use the
 * same terminology as the TPM. in the TPM it's called "extending a hash".
 * the method get_data needs to be renamed IAW java standard convention,
 * either data() or getBytes() or toByteArray().
 */
public class SHA1HashBuilder {
	private byte[] _data = null;

	public SHA1HashBuilder() {
		initialize();
	}

	public void append(byte[] dataToAppend) {
//		checkIsInitialized();

		if (dataToAppend != null) {

			byte[] combined = new byte[getLength() + dataToAppend.length];

			System.arraycopy(_data, 0, combined, 0, getLength());
			System.arraycopy(dataToAppend, 0, combined, getLength(),
					dataToAppend.length);

			_data = sha1(combined);
		}
	}

	private int getLength() {
		// TODO Auto-generated method stub
		return _data.length;
	}

	private  byte[] sha1(final byte[] input)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(input);
			byte[] digest = md.digest();
			return digest;
		} catch (NoSuchAlgorithmException e) {
			throw new ASException(e);
		}
	}
	private void initialize() {

		if (_data == null) {
			_data = new byte[20];
			for(int i = 0; i< 20 ; i++ ) {
				_data[i] =0;
                        }
		}

	}

	public byte[] get_data() {
		return _data;
	}

}
