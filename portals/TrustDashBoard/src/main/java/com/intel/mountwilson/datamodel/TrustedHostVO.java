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

/**
 * 
 */
package com.intel.mountwilson.datamodel;

import org.codehaus.jackson.annotate.JsonProperty;

/**
 * @author yuvrajsx
 *
 */
public class TrustedHostVO {
	
	@JsonProperty("host_name")
	private String hostName;
	private String osName;
	private String hypervisorName;
	
	@JsonProperty("bios_status")
	private String biosStatus;
	
	@JsonProperty("vmm_status")
	private String vmmStatus;
	
	private String overAllStatus;
	private boolean overAllStatusBoolean;
	
	private boolean vmm;
	
	@JsonProperty("error_code")
	private long errorCode;
	
	@JsonProperty("error_message")
	private String errorMessage;
	
	private String updatedOn;
	private String hostID;
	private String location;
        
        
        
        @JsonProperty("asset_tag_status")
        private String assetTagStatus;
        
        @JsonProperty("asset_tag_details")
        private String assetTagDetails;

	

	/**
	 * @return the hostID
	 */
	public String getHostID() {
		return hostID;
	}

	/**
	 * @param string the hostID to set
	 */
	public void setHostID(String string) {
		this.hostID = string;
	}

	/**
	 * @return the vmm
	 */
	public boolean isVmm() {
		return vmm;
	}

	/**
	 * @param vmm the vmm to set
	 */
	public void setVmm(boolean vmm) {
		this.vmm = vmm;
	}

	/**
	 * @return the updatedOn
	 */
	public String getUpdatedOn() {
		return updatedOn;
	}

	/**
	 * @param updatedOn the updatedOn to set
	 */
	public void setUpdatedOn(String updatedOn) {
		this.updatedOn = updatedOn;
	}

	/**
	 * @return the hostName
	 */
	public String getHostName() {
		return hostName;
	}

	/**
	 * @return the osName
	 */
	public String getOsName() {
		return osName;
	}

	/**
	 * @return the hypervisorName
	 */
	public String getHypervisorName() {
		return hypervisorName;
	}

	/**
	 * @return the biosStatus
	 */
	public String getBiosStatus() {
		return biosStatus;
	}

	/**
	 * @return the vmmStatus
	 */
	public String getVmmStatus() {
		return vmmStatus;
	}

	/**
	 * @return the overAllStatus
	 */
	public String getOverAllStatus() {
		return overAllStatus;
	}

	/**
	 * @return the errorCode
	 */
	public long getErrorCode() {
		return errorCode;
	}

	/**
	 * @return the errorMessage
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	/**
	 * @param hostName the hostName to set
	 */
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	/**
	 * @param osName the osName to set
	 */
	public void setOsName(String osName) {
		this.osName = osName;
	}

	/**
	 * @param hypervisorName the hypervisorName to set
	 */
	public void setHypervisorName(String hypervisorName) {
		this.hypervisorName = hypervisorName;
	}

	/**
	 * @param biosStatus the biosStatus to set
	 */
	public void setBiosStatus(String biosStatus) {
		this.biosStatus = biosStatus;
	}

	/**
	 * @param vmmStatus the vmmStatus to set
	 */
	public void setVmmStatus(String vmmStatus) {
		this.vmmStatus = vmmStatus;
	}

	/**
	 * @param overAllStatus the overAllStatus to set
	 */
	public void setOverAllStatus(String overAllStatus) {
		this.overAllStatus = overAllStatus;
	}

	/**
	 * @param errorCode the errorCode to set
	 */
	public void setErrorCode(long errorCode) {
		this.errorCode = errorCode;
	}

	/**
	 * @param errorMessage the errorMessage to set
	 */
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	/**
	 * @return the overAllStatusBoolean
	 */
	public boolean isOverAllStatusBoolean() {
		return overAllStatusBoolean;
	}

	/**
	 * @param overAllStatusBoolean the overAllStatusBoolean to set
	 */
	public void setOverAllStatusBoolean(boolean overAllStatusBoolean) {
		this.overAllStatusBoolean = overAllStatusBoolean;
	}

	
	/**
	 * @return the location
	 */
	public String getLocation() {
		return location;
	}

	/**
	 * @param location the location to set
	 */
	public void setLocation(String location) {
		this.location = location;
	}
        
        
        public String getAssetTagStatus() {
            return assetTagStatus;
        }

        public void setAssetTagStatus(String assetTagStatus) {
            this.assetTagStatus = assetTagStatus;
        }

        public String getAssetTagDetails() {
            return assetTagDetails;
        }

        public void setAssetTagDetails(String assetTagDetails) {
            this.assetTagDetails = assetTagDetails;
        }
        
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "TrustedHostVO [hostName=" + hostName + ", osName=" + osName
				+ ", hypervisorName=" + hypervisorName + ", biosStatus="
				+ biosStatus + ", vmmStatus=" + vmmStatus + ", overAllStatus="
				+ overAllStatus + ", overAllStatusBoolean="
				+ overAllStatusBoolean + ", vmm=" + vmm + ", errorCode="
				+ errorCode + ", errorMessage=" + errorMessage + ", updatedOn="
				+ updatedOn + ", hostID=" + hostID + ", location=" + location
				+ "]";
	}
	
}
