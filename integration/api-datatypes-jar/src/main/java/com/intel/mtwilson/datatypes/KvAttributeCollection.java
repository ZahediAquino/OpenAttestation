/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.datatypes;

//import com.fasterxml.jackson.annotation.JsonInclude;
//import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.codehaus.jackson.map.annotate.JsonSerialize;
//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
//import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.intel.mtwilson.datatypes.DocumentCollection;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import org.codehaus.jackson.annotate.JsonProperty;

/**
 *
 * @author ssbangal
 */
//@JacksonXmlRootElement(localName="kv_attribute_collection")
@XmlRootElement(name = "kv_attribute_collection")
public class KvAttributeCollection extends DocumentCollection<KvAttribute> {
    private final ArrayList<KvAttribute> kvAttributes = new ArrayList<KvAttribute>();
    
    @JsonSerialize(include=JsonSerialize.Inclusion.ALWAYS) // jackson 1.9
    @XmlElementWrapper(name="kv_attributes")
//    @JsonInclude(JsonInclude.Include.ALWAYS)                // jackson 2.0
//    @JacksonXmlElementWrapper(localName="kv_attributes")
//    @JacksonXmlProperty(localName="kv_attribute")    
    @JsonProperty("kv_attributes")
    public List<KvAttribute> getKvAttributes() { return kvAttributes; }

    @Override
    public List<KvAttribute> getDocuments() {
        return getKvAttributes();
    }
    
}
