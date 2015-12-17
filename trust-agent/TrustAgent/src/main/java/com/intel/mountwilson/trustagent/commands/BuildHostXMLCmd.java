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

package com.intel.mountwilson.trustagent.commands;

//import com.intel.mountwilson.common.CommandUtil;
import com.intel.mountwilson.common.CommandUtil;
import com.intel.mountwilson.common.ICommand;
import com.intel.mountwilson.trustagent.data.TADataContext;
import org.apache.commons.lang.StringEscapeUtils;
//import java.util.Date;
//import org.apache.commons.codec.binary.Base64;
//import org.apache.commons.lang.StringEscapeUtils;

/**
 *
 * @author dsmagadX
 */
public class BuildHostXMLCmd implements ICommand {

    private TADataContext context = null;

    public BuildHostXMLCmd(TADataContext context) {
        this.context = context;
    }

    @Override
    public void execute() {

        String responseXML =
                "<host_info_request> "
                + "<clientIp>" + CommandUtil.getHostIpAddress() + "</clientIp>"                
                + "<hardware_uuid>" + context.getHostUUID()+ "</hardware_uuid>"
                + "<error_code>" + context.getErrorCode().getErrorCode() + "</error_code>"
                + "<error_message>" + StringEscapeUtils.escapeXml(context.getErrorCode().getMessage()) + "</error_message>"
                + "</host_info_request>";

        context.setResponseXML(responseXML);
    }
}
