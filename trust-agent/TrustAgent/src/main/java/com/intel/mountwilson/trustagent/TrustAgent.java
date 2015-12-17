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
package com.intel.mountwilson.trustagent;

import com.intel.mountwilson.common.*;
import com.intel.mountwilson.trustagent.commands.*;
import com.intel.mountwilson.trustagent.data.TADataContext;
import com.intel.mountwilson.trustagent.hostinfo.HostInfoCmd;
import java.io.File;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dsmagadX
 */
public class TrustAgent {

    static Logger log = LoggerFactory.getLogger(TrustAgent.class.getName());

    public TrustAgent() {
        TADataContext context = new TADataContext();
        try {
            File file = new File(context.getDataFolder());


            if (!file.isDirectory()) {
                file.mkdir();
                log.info("Data folder was not there created : " + context.getDataFolder());
            }


        } catch (Exception e) {
            log.error( "Error while creating data folder ", e);
        }

    }

    public boolean takeOwnerShip() {
        TADataContext context = new TADataContext();
        try {
            new TakeOwnershipCmd(context).execute();
        } catch (Exception e) {
            log.error( null, e);
            return false;
        }
        return true;
    }

    public String processRequest(String xmlInput) {
        if (xmlInput.contains("quote_request")) {
            log.info("Quote request received");
            return processQuoteRequestInput(xmlInput);
        } else if (xmlInput.contains("identity_request")) {
            return processIdentityRequestInput(xmlInput);
        } else if(xmlInput.contains("host_info_request")){
            log.debug("Got host info request");
            return processHostInfoRequestInput(xmlInput);
        }
        else{
            return generateErrorResponse(ErrorCode.BAD_REQUEST);
        }
    }
    
    private String processHostInfoRequestInput(String xmlInput) {
        try {
            log.info("processHostInfoRequestInput, got xmlInput: "+ xmlInput);
            TADataContext context = new TADataContext();
//
//            context.setNonce(getNonce(xmlInput));
//            context.setSelectedPCRs(getSelectedPCRs(xmlInput));
////
//            validateCertFile();
//
//            new CreateNonceFileCmd(context).execute();
//            new GenerateModulesCmd(context).execute(); 
            log.info("About to run the HostInfoCmd");
            new HostInfoCmd(context).execute();
//            new ReadIdentityCmd(context).execute();
//            new GenerateQuoteCmd(context).execute();
            //new BuildQuoteXMLCmd(context).execute();
            new BuildHostXMLCmd(context).execute();
            log.info("getResponseXML: " + context.getResponseXML());

            return context.getResponseXML();

        } catch (TAException ex) {
            log.error( null, ex);
            return generateErrorResponse(ex.getErrorCode(), ex.getMessage());
        }
    }

    private String processQuoteRequestInput(String xmlInput) {
        try {
            TADataContext context = new TADataContext();

            context.setNonce(getNonce(xmlInput));
            context.setSelectedPCRs(getSelectedPCRs(xmlInput));

            validateCertFile();

            new CreateNonceFileCmd(context).execute();
            new GenerateModulesCmd(context).execute(); 
            new ReadIdentityCmd(context).execute();
            new GenerateQuoteCmd(context).execute();
            new BuildQuoteXMLCmd(context).execute();
            log.info("getResponseXML: " + context.getResponseXML());

            return context.getResponseXML();

        } catch (TAException ex) {
            log.error( null, ex);
            return generateErrorResponse(ex.getErrorCode(), ex.getMessage());
        }
    }

    private String processIdentityRequestInput(String xmlInput) {
        try {
            TADataContext context = new TADataContext();

            new CreateIdentityCmd(context).execute();
            new BuildIdentityXMLCmd(context).execute();

            return context.getResponseXML();

        } catch (TAException ex) {
           log.error("Error in processIdentityRequestInput", ex);
            return generateErrorResponse(ex.getErrorCode(), ex.getMessage());
        }

    }

    public String generateErrorResponse(ErrorCode errorCode) {

        String responseXML =
                "<client_request> "
                + "<vtime>" + new Date(System.currentTimeMillis()).toString() + "</vtime>"
                + "<clientIp>" + CommandUtil.getHostIpAddress() + "</clientIp>"
                + "<error_code>" + errorCode.getErrorCode() + "</error_code>"
                + "<error_message>" + errorCode.getMessage() + "</error_message>"
                + "</client_request>";
        return responseXML;
    }

    public String generateErrorResponse(ErrorCode errorCode, String errorMsg) {

        String responseXML =
                "<client_request> "
                + "<vtime>" + new Date(System.currentTimeMillis()).toString() + "</vtime>"
                + "<clientIp>" + CommandUtil.getHostIpAddress() + "</clientIp>"
                + "<error_code>" + errorCode.getErrorCode() + "</error_code>"
                + "<error_message>" + errorCode.getMessage() + " " + errorMsg + "</error_message>"
                + "</client_request>";
        return responseXML;
    }

    private String getNonce(String xmlInput) throws TAException {

        try {
            Pattern p = Pattern.compile("<nonce>([^\"><]*?)</nonce>"); // constrained regex from .* to [^\"><]
            Matcher m = p.matcher(xmlInput);
            m.find();
            String nonce = m.group(1);
            log.info("Nonce {}", nonce);
            return nonce;
        } catch (Exception e) {
            throw new TAException(ErrorCode.BAD_REQUEST, "Cannot find nonce in the input xml");
        }

    }

    private String getSelectedPCRs(String xmlInput) throws TAException {
        try {
            Pattern p = Pattern.compile("<pcr_list>([^\"><]*?)</pcr_list>"); // constrained regex from .* to [^\"><]
            Matcher m = p.matcher(xmlInput);
            m.find();
            String pcrList = m.group(1);

            return validateAndFormat(pcrList);
        } catch (Exception e) {
            throw new TAException(ErrorCode.BAD_REQUEST, "Cannot find pcr_list in the input xml");
        }

    }

    private String validateAndFormat(String pcrList) throws TAException {
        String parts[] = pcrList.split(",");
        StringBuilder pcrInput = new StringBuilder("");
        Set<Integer> pcrs = new HashSet<Integer>();

        try {
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].contains("-")) {

                    String[] subParts = parts[i].split("-");

                    int start = Integer.parseInt(subParts[0]);
                    int end = Integer.parseInt(subParts[1]);

                    if (start > end) {
                        throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("Start %d is greater than end %d", start, end));
                    }

                    for (int pcr = start; pcr <= end; pcr++) {
                        if (pcr >= 0 && pcr <= 23) {
                            pcrs.add(pcr);
                        }
                    }

                } else {
                    int pcr = Integer.parseInt(parts[i]);

                    if (pcr >= 0 && pcr <= 23) {
                        //pcrInput += (pcrInput.length() == 0) ? pcr : " " + pcr;
                        pcrs.add(pcr);
                    } else {
                        throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("PCR %d not in range 1-23", pcr));
                    }
                }
            }

            if (pcrs.isEmpty()) {
                throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("PCR list is empty.", pcrList));
            }

            for (Integer pcr : pcrs) {
                if (pcrInput.length() == 0) {
                    pcrInput.append(pcr.toString());
                } else {
                    pcrInput.append(" " + pcr);
                }

            }

        } catch (NumberFormatException e) {
            throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("PCR list [%s] contains a non number.", pcrList));
        }
        log.info("PCR List {}", pcrInput);
        return pcrInput.toString();
    }

    private void validateCertFile() {
    }

}
