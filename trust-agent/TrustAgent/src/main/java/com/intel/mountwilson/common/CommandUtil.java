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
package com.intel.mountwilson.common;

import com.intel.mountwilson.trustagent.datatype.IPAddress;
import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 *
 * @author dsmagadX
 */
public class CommandUtil {

    private static final Logger log = LoggerFactory.getLogger(CommandUtil.class.getName());
    
    
    public static List<String> runCommand(String commandLine) throws TAException, IOException {
	     return runCommand(commandLine, null);
    }
    
    public static List<String> runCommand(String commandLine, String[] envp) throws TAException, IOException {


        if(StringUtils.isBlank(commandLine))
            throw new TAException(ErrorCode.ERROR,"Command cannot be empty.");
        
        String[] command = commandLine.split(" ");
        
        if(new File(Config.getBinPath() + File.separator + command[0]).exists())
            commandLine = Config.getBinPath() + File.separator + commandLine;
//        commandLine = System.getProperty("app.path", ".") + "/bin/./" + commandLine;
        if(new File(Config.getBinPath() + File.separator + commandLine).exists())
            commandLine = Config.getBinPath() + File.separator + commandLine;
        

        if (Config.isDebug()) {
            log.info( "commandLine: " + commandLine);
        }

        Process p;
        if( envp == null ) {
           p = Runtime.getRuntime().exec(commandLine);
        }
        else {
           p = Runtime.getRuntime().exec(commandLine, envp);
        }

        List<String> result = new ArrayList<String>();

        readResults(p, result);

//        if (Config.isDebug()) {
//            log.log(Level.INFO, "Result Output \n{0}", (result == null ) ? "null":result.toString());
//        }

        //do a loop to wait for an exit value
        boolean isRunning;
        int timeout = 500000;
        int countToTimeout = 0;
        do {
            countToTimeout++;
            isRunning = false;
            try {
                p.exitValue();

            } catch (IllegalThreadStateException e1) {
                isRunning = true;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e2) {
                    isRunning = false;
                }
            }
        } while (isRunning
                && (countToTimeout < timeout));

        if (countToTimeout
                == timeout) {
            log.info("Command is not responding.");
            p.destroy();

        }

        checkError(p.exitValue(), commandLine);


        return result;
    }
    
     public static CommandResult runCommand2(String commandLine) throws TAException, IOException {
        return runCommand2(commandLine, null);
    }
    
    public static CommandResult runCommand2(String commandLine, String[] envp) throws TAException, IOException {
        
        if(StringUtils.isBlank(commandLine))
            throw new TAException(ErrorCode.ERROR,"Command cannot be empty.");
        
        String[] command = commandLine.split(" ");
        
        if(new File(Config.getBinPath() + File.separator + command[0]).exists())
            commandLine = Config.getBinPath() + File.separator + commandLine;

        if(new File(Config.getBinPath() + File.separator + commandLine).exists())
            commandLine = Config.getBinPath() + File.separator + commandLine;
        
        log.debug("Command to be executed is :" + commandLine);

        Process p;
        if( envp == null ) {
            p = Runtime.getRuntime().exec(commandLine);
        }
        else {
            p = Runtime.getRuntime().exec(commandLine, envp);
        }
        // read stdout
        InputReader stdout = new InputReader(p.getInputStream());
        Thread stdoutThread = new Thread(stdout);
        stdoutThread.start();
        // read stderr
        InputReader stderr = new InputReader(p.getErrorStream());
        Thread stderrThread = new Thread(stderr);
        stderrThread.start();
        CommandResult result = new CommandResult();
        try {
        // wait until the process exits
        result.exitcode = p.waitFor();
        // after the process exits the stdout and stderr threads will terminate
        stdoutThread.join(); // throws InterruptedException
        stderrThread.join(); // throws InterruptedException
        }
        catch(InterruptedException e) {
            log.error("Interrupted", e);
        }
        
        log.debug("stdout:\n{}", stdout.getResult());
        log.debug("stderr:\n{}", stderr.getResult());

        result.command = commandLine;
        result.stdout = stdout.getResult();
        result.stderr = stderr.getResult();

        if( result.exitcode != 0 ) {
            throw new TAException(ErrorCode.FATAL_ERROR, result.exitcode + ": Error while running command: " + commandLine);            
        }

        return result;
    }

    private static void checkError(int exitValue, String commandLine) throws TAException {
        log.info( "Return code: " + exitValue);

        if (exitValue == 1) {
            throw new TAException(ErrorCode.FATAL_ERROR, "Error while running command" + commandLine);
        }


    }

    private static void readResults(Process p, List<String> result) throws IOException {
        BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));


        try {
            String newLine;
            while ((newLine = input.readLine()) != null) {
                result.add(newLine);
            }
        } finally {
            input.close();
        }


    }

    public static byte[] readfile(String fileName) throws TAException {

        try (InputStream fStream = new FileInputStream(fileName)) {
            int fileLength = (int) new File(fileName).length();
            //fStream = new FileInputStream(fileName);
            byte[] fileContents = new byte[fileLength];
            int read = fStream.read(fileContents);
            if (read != fileLength) {
                log.warn("Lenght of file read is not same as file length");
            }
            return fileContents;
        } catch (Exception ex) {
            throw new TAException(ErrorCode.ERROR, "Error while reading cert", ex);
        }


    }

    public static String readCertificate(String fileName) throws TAException {
        try {
            javax.security.cert.X509Certificate cert = javax.security.cert.X509Certificate.getInstance(readfile(fileName));
            //        return "-----BEGIN CERTIFICATE-----" + new String(Base64.encodeBase64(cert.getEncoded())) + "-----END CERTIFICATE-----";
            // Important: the certificate data MUST be chunked to 76 character blocks for proper interpretation by openssl on the client.
            // TODO:removed this till we fix AS
            return "-----BEGIN CERTIFICATE-----"
                    + new String(Base64.encodeBase64(cert.getEncoded(), true))
                    + "-----END CERTIFICATE-----";


//			return "-----BEGIN CERTIFICATE-----\n"
//					+ new String(Base64.encodeBase64Chunked(cert.getEncoded()))
//					+ "-----END CERTIFICATE-----";
        } catch (Exception e) {
            throw new TAException(ErrorCode.ERROR, "Error while reading AIK Cert", e);
        }
    }

    public static String getHostIpAddress() {
        String localIpAddress = "127.0.0.1";
        Enumeration<NetworkInterface> networkInterface;
        try {

            networkInterface = NetworkInterface.getNetworkInterfaces();
            for (; networkInterface.hasMoreElements();) {
                NetworkInterface e = networkInterface.nextElement();
                log.info( "Interface: {}", new Object[]{e.getName()});
                Enumeration<InetAddress> ad = e.getInetAddresses();
                for (; ad.hasMoreElements();) {
                    InetAddress addr = ad.nextElement();
                    String returnIpAddress = addr.getHostAddress();
                    if (!returnIpAddress.equals(localIpAddress) && IPAddress.isValid(returnIpAddress)) {
                        return returnIpAddress;
                    } else {
                        log.info("{} == {} or ip validation failed.", new Object[]{returnIpAddress, localIpAddress});
                    }
                }
            }

        } catch (Exception ex) {
            log.error("Error while getting the network interfaces returning 127.0.0.1", ex);
        }
        return localIpAddress;
    }

    public static String generateErrorResponse(ErrorCode errorCode) {

        String responseXML =
                "<client_request> "
                + "<vtime>" + new Date(System.currentTimeMillis()).toString() + "</vtime>"
                + "<clientIp>" + StringEscapeUtils.escapeXml(CommandUtil.getHostIpAddress()) + "</clientIp>"
                + "<error_code>" + errorCode.getErrorCode() + "</error_code>"
                + "<error_message>" + StringEscapeUtils.escapeXml(errorCode.getMessage()) + "</error_message>"
                + "</client_request>";
        return responseXML;
    }
    
    
}
