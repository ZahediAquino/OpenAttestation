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
package com.intel.mountwilson.datamodel;


public class HostType {
    
    public static enum hostOS{
    	VMWARE_OS("vmware","vmware.png", "false"),
        UBUNTU("ubuntu","ubuntu.png","true"),
        SUSE("suse","suse.png","true"),
        RHEL("rhel","rhel.png","true"),
        FEDORA("fedora","fedora.png","true"),
        RED_HAT("redhat","rhel.png","true"),
        CITRIX_XENSERVER("xenserver","citrix.png","false");
        
        private String value;
        private String imageName;
        private String vmmImageNeeded;

        public String getVmmImageNeeded() {
            return vmmImageNeeded;
        }

        public void setVmmImageNeeded(String vmmImageNeeded) {
            this.vmmImageNeeded = vmmImageNeeded;
        }


    	private hostOS(String value, String imageName, String vmmImageNeeded) {
    		this.value = value;
    		this.imageName = imageName;
                this.vmmImageNeeded = vmmImageNeeded;
    	}

    	public String getValue() {
    		return value;
    	}

    	public void setValue(String value) {
    		this.value = value;
    	}

    	public String getImageName() {
    		return imageName;
    	}

    	public void setImageName(String imageName) {
    		this.imageName = imageName;
    	}
    }
    
    public static enum hostVMM{
    	QEMU("qemu","kvm.png"),
        KVM("kvm","kvm.png"),
        XEN("xen","xen.png");
       
        
        private String value;
        private String imageName;


    	private hostVMM(String value, String imageName) {
    		this.value = value;
    		this.imageName = imageName;
    	}


		public String getValue() {
			return value;
		}


		public void setValue(String value) {
			this.value = value;
		}


		public String getImageName() {
			return imageName;
		}


		public void setImageName(String imageName) {
			this.imageName = imageName;
		}
    	
    }
    
    
}
