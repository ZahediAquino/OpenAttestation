/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.datatypes;

//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;


/**
 *
 * @author ssbangal
 */
//@JacksonXmlRootElement(localName="selection")
public class Selection extends Document{
        
    private String name;
    private String description;    
    
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
    
}
