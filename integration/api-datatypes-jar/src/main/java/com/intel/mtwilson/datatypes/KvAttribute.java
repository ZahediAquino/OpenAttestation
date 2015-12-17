/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.datatypes;

//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import javax.xml.bind.annotation.XmlRootElement;
//import com.intel.mtwilson.util.io.UUID;
//import com.intel.mtwilson.jaxrs2.Document;

/**
 *
 * @author ssbangal
 */
//@JacksonXmlRootElement(localName="kv_attribute")
@XmlRootElement(name = "kv_attribute")
public class KvAttribute extends Document{
    
    private String name;
    private String value;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }    
    
}
