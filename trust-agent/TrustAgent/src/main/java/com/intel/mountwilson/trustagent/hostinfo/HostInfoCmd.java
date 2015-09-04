/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mountwilson.trustagent.hostinfo;

import com.intel.mountwilson.common.CommandResult;
import com.intel.mountwilson.common.CommandUtil;
import com.intel.mountwilson.common.ErrorCode;
import com.intel.mountwilson.common.ICommand;
import com.intel.mountwilson.common.TAException;
import com.intel.mountwilson.trustagent.data.TADataContext;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * @author dsmagadx
 */
public class HostInfoCmd implements ICommand {
    //private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(HostInfoCmd.class);
    Logger log = LoggerFactory.getLogger(getClass().getName());
    private TADataContext context;
    //TADataContext context = null;

    public HostInfoCmd(TADataContext context) {
        this.context = context;
    }

    @Override
    public void execute() throws TAException {
        try {

//            getOsAndVersion();
//            getBiosAndVersion();
//            if(context.getOsName() != null &&  context.getOsName().toLowerCase().contains("xenserver")){
//                context.setVmmName(context.getOsName());
//                context.setVmmVersion(context.getOsVersion());
//                log.debug("VMM Name: " + context.getVmmName());
//                log.debug("VMM Version: " + context.getVmmVersion());
//
//            }else{
//                getVmmAndVersion();
//            
//            }
//            // Retrieve the processor information as well.
//            getProcessorInfo();
            log.info("Getting the hosts UUID...");
            getHostUUID();
        } catch (Exception ex) {
            log.debug("Error while getting Host details", ex);
            throw new TAException(ErrorCode.ERROR, "Error while getting Host details.", ex);
        }

    }
//
//    /*
//    Sample response of "lsb_release -a" 
//    No LSB modules are available.
//    Distributor ID: Ubuntu
//    Description:    Ubuntu 11.10
//    Release:        11.10
//    Codename:       oneiric
//     */
//    
//    private void getOsAndVersion() throws TAException, IOException {
//        CommandResult commandResult = CommandUtil.runCommand("tagent system-info lsb_release -a");
//        if (commandResult != null && commandResult.getStdout() != null) {
//            String[] result = commandResult.getStdout().split("\n");
//            for (String str : result) {
//                String[] parts = str.split(":");
//
//                if (parts != null && parts.length > 1) {
//                    if (parts[0].trim().equalsIgnoreCase("Distributor ID")) {
//                        if (parts[1] != null) {
//                            context.setOsName(parts[1].trim());
//                        }
//                    } else if (parts[0].trim().equalsIgnoreCase("Release")) {
//                        if (parts[1] != null) {
//                            context.setOsVersion(parts[1].trim());
//                        }
//
//                    }
//                }
//            }
//            log.debug("OS Name: " + context.getOsName());
//            log.debug("OS Version: " + context.getOsVersion());
//        } else {
//            log.error("Error executing the lsb_release command to retrieve the OS details");
//        }
//            
//    }
// Not used method    
//    private String trim(String text) {
//        if( text == null ) { return null; }
//        return text.trim();
//    }
//
//    /*
//     * Sample response of dmidecode -s bios-vendor -> Intel Corp. Sample
//     * response of dmidecode -s bios-vendor -> S5500.86B.01.00.0060.090920111354
//     */
//    private void getBiosAndVersion() throws TAException, IOException {
//        CommandResult result = CommandUtil.runCommand("tagent system-info dmidecode -s bios-vendor");
//        List<String> resultList = Arrays.asList(result.getStdout().split("\n"));
//        if (resultList != null && resultList.size() > 0) {
//            for (String data : resultList) {
//                if (data.trim().startsWith("#")) // ignore the comments
//                    continue;
//                context.setBiosOem(data.trim());
//                break;
//            }
//        }
//        log.debug("Bios OEM: " + context.getBiosOem());
//
//        CommandResult result2 = CommandUtil.runCommand("tagent system-info dmidecode -s bios-version");
//        resultList = Arrays.asList(result2.getStdout().split("\n"));
//        if (resultList != null && resultList.size() > 0) {
//            for (String data : resultList) {
//                if (data.trim().startsWith("#")) // ignore the comments
//                    continue;
//                context.setBiosVersion(data.trim());
//                break;
//            }
//        }
//        log.debug("Bios Version: " + context.getBiosVersion());
//    }
//    /*
//     * Sample response of "virsh version" command: 
//     * root@mwdevubuk02h:~# virsh version 
//     * Compiled against library: libvir 0.9.2 
//     * Using library: libvir 0.9.2 
//     * Using API: QEMU 0.9.2 
//     * Running hypervisor: QEMU 0.14.1
//     */
//
//    private void getVmmAndVersion() throws TAException, IOException {
//
//        CommandResult commandResult = CommandUtil.runCommand("tagent system-info virsh version");
//        if (commandResult != null && commandResult.getStdout() != null) {
//            String[] result = commandResult.getStdout().split("\n");
//
//            for (String str : result) {
//                String[] parts = str.split(":");
//
//                if (parts != null && parts.length > 1) {
//                    if (parts[0].trim().equalsIgnoreCase("Running hypervisor")) {
//                        if (parts[1] != null) {
//                            String[] subParts = parts[1].trim().split(" ");
//                            if (subParts[0] != null) {
//                                context.setVmmName(subParts[0]);
//                            }
//                            if (subParts[1] != null) {
//                                context.setVmmVersion(subParts[1]);
//                            }
//                        }
//                    }
//                }
//                log.debug("VMM Name: " + context.getVmmName());
//                log.debug("VMM Version: " + context.getVmmVersion());
//            }
//        } else {
//            log.error("Error executing the virsh version command to retrieve the hypervisor details.");
//        }
//    }
//
//    /**
//     * Retrieves the CPU ID of the processor. This is used to identify the processor generation.
//     * 
//     * @throws TAException
//     * @throws IOException 
//     */
//       private void getProcessorInfo() throws TAException, IOException {
//           
//            CommandResult commandResult = CommandUtil.runCommand("tagent system-info dmidecode --type processor");
//            if (commandResult != null && commandResult.getStdout() != null) {
//                String[] result = commandResult.getStdout().split("\n");
//                String processorInfo = "";
//
//                // Sample output would look like below for a 2 CPU system. We will extract the processor info between CPU and the @ sign
//                //Processor Information
//                //Socket Designation: CPU1
//                //Type: Central Processor
//                //Family: Xeon
//                //Manufacturer: Intel(R) Corporation
//                //ID: C2 06 02 00 FF FB EB BF -- This is the CPU ID
//                //Signature: Type 0, Family 6, Model 44, Stepping 2
//
//                for (String entry : result) {
//                    if (entry != null && !entry.isEmpty() && entry.trim().startsWith("ID:")) {                    
//                        String[] parts = entry.trim().split(":");
//                         if (parts != null && parts.length > 1) {
//                            processorInfo = parts[1];
//                            break;
//                         }
//                    }            
//                }
//
//                log.debug("Processor Information " + processorInfo);
//                context.setProcessorInfo(processorInfo);
//                log.debug("Context is being set with processor info: " + context.getProcessorInfo());
//            } else {
//                log.error("Error retrieving the processor information");
//            }
//    }
    
    /**
     * Retrieves the host UUId information
     * @throws TAexception
     * @throws IOException
     */
    public void getHostUUID() throws TAException, IOException {
        //CommandResult result = CommandUtil.runCommand2("tagent system-info dmidecode -s system-uuid");
        CommandResult result = CommandUtil.runCommand2("dmidecode -s system-uuid");
        // sample output would look like: 4235D571-8542-FFD3-5BFE-6D9DAC874C84
        if(null != result.getStdout())
        {
            List<String> resultList = Arrays.asList(result.getStdout().split("\n"));

            if (resultList != null && resultList.size() > 0) {
                for (String data : resultList) {
                    if (data.trim().startsWith("#")) { // ignore the comments
                        continue;
                    }
                    context.setHostUUID(data.trim());
                    log.info("got uuid data: {}", data.trim());
                    break;
                }
            }

            log.info("Context set with host UUID info: " + context.getHostUUID());
            //context.setResponseXML(null);
        }
    }
}
