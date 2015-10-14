/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.as.business.trust;

import com.intel.mountwilson.as.common.ASConfig;
import com.intel.mountwilson.as.common.ASException;
import com.intel.mtwilson.as.helper.ASComponentFactory;
import com.intel.mtwilson.datatypes.BulkHostTrustResponse;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.datatypes.HostTrust;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jbuhacoff
 */
public class BulkHostTrustBO {
    private Logger log = LoggerFactory.getLogger(getClass());
    private HostTrustBO hostTrustBO = ASComponentFactory.getHostTrustBO1(); 
//    private int maxThreads;
    private int timeout;
    //private static ExecutorService scheduler = Executors.newFixedThreadPool(ASConfig.getConfiguration().getInt("mtwilson.bulktrust.threads.max", 32)); //  bug #503 move thread pool to static so multiple requests do not overload it; 
    
    public BulkHostTrustBO(/*int maxThreads,*/ int timeout) {
//        this.maxThreads = maxThreads;
        this.timeout = timeout;
    }
    
    public String getBulkTrustSaml(Set<String> hosts, boolean forceVerify) {
        try {
            Set<HostQuoteSaml> tasks = new HashSet<>();
            //ArrayList<Future<?>> taskStatus = new ArrayList<>();
            
            
            List<String> results = new ArrayList<>();
            
            for(String host : hosts) {
                HostQuoteSaml task = new HostQuoteSaml(hostTrustBO, host, forceVerify);
                task.getTrustWithSaml();
                tasks.add(task);
               // Future<?> status = scheduler.submit(task);
                //taskStatus.add(status);
            }
            
            // Bug:547 - Since the comment mentioned that the return value will not be used and the java.util.concurrent.TimeoutException was being thrown
            // by the get statement, we are ignoring the exception and continuing.
            /*
            for (Future<?> status : taskStatus) {
                try {
                    status.get(timeout, TimeUnit.SECONDS); // return value will always be null because we submitted "Runnable" tasks
                } catch (InterruptedException | ExecutionException | TimeoutException ex) {
                    // we will log the exception and ignore the error.
                    log.error("Exception while retrieving the status of the tasks. {}", ex.getMessage());
                }
            }*/
//            scheduler.shutdown(); //  bug #503 remove this and replace with calls to Future.get() to get all our results
            
//            if( scheduler.awaitTermination(timeout, TimeUnit.SECONDS) ) { //  bug #503 replace with waiting for all Futures that WE SUBMITTED to return (because in static thread pool other requests may be submitting tasks to the same pool... we don't want to wait for all of them, jus tours )
//                log.info("All tasks completed on time");
//            }
//            else {
//                log.info("Timeout reached before all tasks completed"); // should set the error code ErrorCode.AS_ASYNC_TIMEOUT on the ones that timed out (no result available)
//            }
            
            for(HostQuoteSaml task : tasks) {
                if( task.getResult() == null ) {
                    results.add(task.getTimeoutResult());
                }
                else if( task.isError() ) {
                    results.add(task.getResult()); // already an error response
                }
                else {
                    results.add(task.getResult());
                }
            }
            
            //String report = String.format("<Hosts>%s</Hosts>", StringUtils.join(results, ""));
            String report = StringUtils.join(results, "");

            return report;
        } catch (Exception ex) {
            // throw new ASException(ex);
            // Bug: 1038 - prevent leaks in error messages to client
            log.error("Error during bulk host trust retrieval.", ex);
            throw new ASException(ErrorCode.AS_BULK_HOST_TRUST_ERROR, ex.getClass().getSimpleName());
        }
    }
    /*
    public BulkHostTrustResponse getBulkTrustJson(Set<String> hosts, boolean forceVerify) {
        try {
                        
            Set<HostQuoteJson> tasks = new HashSet<HostQuoteJson>();
//            ExecutorService scheduler = Executors.newFixedThreadPool(maxThreads);
            ArrayList<Future<?>> taskStatus = new ArrayList<Future<?>>();
            
            List<HostTrust> results = new ArrayList<HostTrust>();
            
            for(String host : hosts) {
                HostQuoteJson task = new HostQuoteJson(hostTrustBO, host, forceVerify);
                tasks.add(task);
                Future<?> status = scheduler.submit(task);
                taskStatus.add(status);
            }
            
            for(Future<?> status : taskStatus) {
                try {
                    status.get(timeout, TimeUnit.SECONDS); // return value will always be null because we submitted "Runnable" tasks
                }
                catch(Exception e) {
                    log.error("Error while waiting for task to complete: {}", e);
                }
            }
            
//            scheduler.shutdown();
            
//            if( scheduler.awaitTermination(timeout, TimeUnit.SECONDS) ) {
//                log.info("All tasks completed on time");
//            }
//            else {
//                log.info("Timeout reached before all tasks completed"); // should set the error code ErrorCode.AS_ASYNC_TIMEOUT on the ones that timed out (no result available)
//            }
            
            
            for(HostQuoteJson task : tasks) {
                if( task.getResult() == null ) {
                    results.add(task.getTimeoutResult());
                }
                else if( task.isError() ) {
                    results.add(task.getResult()); // already in error format
                }
                else {
                    results.add(task.getResult());
                }
            }
            
            BulkHostTrustResponse report = new BulkHostTrustResponse();
            for(HostTrust result : results) {
                report.getHosts().add(result);
            }

            return report;
        } catch (Exception ex) {
            // throw new ASException(ex);
            // Bug: 1038 - prevent leaks in error messages to client
            log.error("Error during bulk host trust retrieval.", ex);
            throw new ASException(ErrorCode.AS_BULK_HOST_TRUST_ERROR, ex.getClass().getSimpleName());
        }
    }*/
    
    //private class HostQuoteSaml implements Runnable {
    private class HostQuoteSaml {
        private HostTrustBO dao;
        private String hostname = null; // example: "10.1.71.174"
        private boolean forceVerify;
        private String result = null;
        private boolean isError = false;
        
        public HostQuoteSaml(HostTrustBO dao, String hostname, boolean forceVerify) {
            this.dao = dao;
            this.hostname = hostname;
            this.forceVerify = forceVerify;
        }
        
        public void getTrustWithSaml() throws IOException {
            try {
                result = dao.getTrustWithSaml(hostname, forceVerify);
                //result = String.format("<Host><Name>%s</Name><ErrorCode>%s</ErrorCode><Assertion><![CDATA[%s]]></Assertion></Host>", hostname, ErrorCode.OK.toString(), saml);
                
            } catch (IOException ex) {
                log.info(ex.getMessage());
            } 
        }
        
        /*
        @Override
        public void run() {
            if( isError() ) { return; } // avoid clobbering previous error
            try {
                result = dao.getTrustWithSaml(hostname, forceVerify);
                //result = String.format("<Host><Name>%s</Name><ErrorCode>%s</ErrorCode><Assertion><![CDATA[%s]]></Assertion></Host>", hostname, ErrorCode.OK.toString(), saml);
                
//                log.info("______________________________________________________________________________________________________________");
//                log.info("(BulkHostTrustBO.java line:178)SAML: " + result);
//                log.info("______________________________________________________________________________________________________________");
            } catch (IOException ex) {
//                java.util.logging.Logger.getLogger(BulkHostTrustBO.class.getName()).log(Level.SEVERE, null, ex);
                log.info(ex.getMessage());
            } 
//            catch(ASException e) {
//                isError = true;
//                result = String.format("<Host><Name>%s</Name><ErrorCode>%s</ErrorCode><ErrorMessage>%s</ErrorMessage></Host>", hostname, e.getErrorCode().toString(), e.getErrorMessage());
//            }
//            catch(Exception e) {
//                isError = true;
//                // result = String.format("<Host><Name>%s</Name><ErrorCode>%s</ErrorCode><ErrorMessage>%s</ErrorMessage></Host>", hostname, ErrorCode.UNKNOWN_ERROR.toString(), e.getLocalizedMessage());
//                result = String.format("<Host><Name>%s</Name><ErrorCode>%s</ErrorCode><ErrorMessage>%s</ErrorMessage></Host>", 
//                        hostname, ErrorCode.AS_HOST_TRUST_ERROR.toString(), String.format(ErrorCode.AS_HOST_TRUST_ERROR.getMessage(), e.getClass().getSimpleName()));
//            }
        }*/
        
        public boolean isError() { return isError; }
        public String getResult() { return result; }
        public String getHostname() { return hostname; }
        public String getTimeoutResult() { return String.format("<Host><Name>%s</Name><ErrorCode>%s</ErrorCode><ErrorMessage>%s</ErrorMessage></Host>", hostname, ErrorCode.AS_ASYNC_TIMEOUT.toString(), "Exceeded timeout of "+timeout+" seconds"); } 
        
    }
    
    private class HostQuoteJson implements Runnable {
        private HostTrustBO dao;
        private String hostname = null; // example: "10.1.71.174"
        private boolean forceVerify;
        private HostTrust result = null;
        private boolean isError = false;
        
        public HostQuoteJson(HostTrustBO dao, String hostname, boolean forceVerify) {
            this.dao = dao;
            this.hostname = hostname;
            this.forceVerify = forceVerify;
        }
        
        @Override
        public void run() {
            if( isError() ) { return; } // avoid clobbering previous error
            try {
                result = dao.getTrustWithCache(hostname, forceVerify);
            }
            catch(ASException e) {
                isError = true;
                result = new HostTrust(e.getErrorCode(),e.getMessage(),hostname, null, null); 
            }
            catch(Exception e) {
                isError = true;
                result = new HostTrust(ErrorCode.AS_HOST_TRUST_ERROR, String.format(ErrorCode.AS_HOST_TRUST_ERROR.getMessage(), e.getClass().getSimpleName()),hostname, null, null); 
            }
        }
        
        public boolean isError() { return isError; }
        public HostTrust getResult() { return result; }
        public String getHostname() { return hostname; }
        public HostTrust getTimeoutResult() { return new HostTrust(ErrorCode.AS_ASYNC_TIMEOUT,"Exceeded timeout of "+timeout+" seconds",hostname, null, null); }

        
    }
    }
