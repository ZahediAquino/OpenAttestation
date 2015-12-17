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
 * This Class contains all Constant variables used in other class while data manipulation.
 */
package com.intel.mountwilson.constant;

/**
 * @author yuvrajsx
 *
 */
public interface HelperConstant {
	
	String IMAGE_TRUSTED_TRUE = "trustTure";
	String IMAGE_TRUSTED_FALSE = "trustFalse";
	String IMAGE_TRUSTED_UNKNOWN = "trustUnknow";
	
	String OS_IMAGE_VMWARE = "vmware";
	
	/*String OS_IMAGE_UBUNTU = "ubuntu";
	String OS_IMAGE_SUSE = "suse";
	String OS_IMAGE_RHEL = "rhel";
	
	String HYPER_IMAGE_KVM = "kvm";
	String HYPER_IMAGE_XEN = "xen";*/
	String SEPARATOR_VMCLIENT = "::";
	String VM_POWER_STATE_ON = "POWERED_ON";
        
	String Trusted_BIOS = "Trusted_BIOS";
	String Trusted_VMM = "Trusted_VMM";
	String OVER_ALL_TRUSTRED = "Trusted";
	
	//Path for Images
	String IMAGES_ROOT_PATH = "imagesRootPath";
	
	// Separator used while displaying vmmInfo in Edit, View and Add host page.
	String OS_VMM_INFORMATION_SEPERATOR = "|";
        String OS_VERSION_INFORMATION_SEPERATOR = ":";
	
	//Separator used in key while storing HostVmMappingVO Object into a map for VM and Host mapping information. 
	String VM_HOST_MAPPING_SEPERATOR = "-";
	
}
