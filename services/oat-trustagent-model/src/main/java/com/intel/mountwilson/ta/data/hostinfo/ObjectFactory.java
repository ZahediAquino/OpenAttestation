//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.2-147 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2012.07.05 at 03:02:52 PM PDT 
//


package com.intel.mountwilson.ta.data.hostinfo;

import com.intel.mountwilson.ta.data.ClientRequestType;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the com.intel.mountwilson.ta.data.hostinfo package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {
    private final static QName _HostInfo_QNAME = new QName("", "host_info");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: com.intel.mountwilson.ta.data.hostinfo
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link HostInfo }
     * 
     */
    public HostInfo createHostInfoType() {
        return new HostInfo();
    }
    
      /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ClientRequestType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "", name = "host_info")
    public JAXBElement<HostInfo> createHostInfo(HostInfo value) {
        return new JAXBElement<HostInfo>(_HostInfo_QNAME, HostInfo.class, null, value);
    }
    /*
      public ClientRequestType createClientRequestType() {
        return new ClientRequestType();
    }

    @XmlElementDecl(namespace = "", name = "client_request")
    public JAXBElement<ClientRequestType> createClientRequest(ClientRequestType value) {
        return new JAXBElement<ClientRequestType>(_ClientRequest_QNAME, ClientRequestType.class, null, value);
    }
    */

}