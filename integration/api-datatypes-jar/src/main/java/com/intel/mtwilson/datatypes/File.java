/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.datatypes;

//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.intel.mtwilson.util.validation.Regex;
import com.intel.mtwilson.datatypes.Document;
import javax.xml.bind.annotation.*;




/**
 * 
 * @author jbuhacoff
 */
//@JacksonXmlRootElement(localName="file")
@XmlRootElement(name="file")
public class File extends Document {
    
    private String name;
    private byte[] content;    
    private String contentType;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
    
}
