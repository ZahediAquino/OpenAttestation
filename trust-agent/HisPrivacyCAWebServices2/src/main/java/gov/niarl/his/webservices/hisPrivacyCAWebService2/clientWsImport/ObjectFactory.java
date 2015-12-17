
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport package. 
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

    private final static QName _GetHisPrivacyCAWebService2_QNAME = new QName("http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", "getHisPrivacyCAWebService2");
    private final static QName _GetHisPrivacyCAWebService2Response_QNAME = new QName("http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", "getHisPrivacyCAWebService2Response");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link GetHisPrivacyCAWebService2 }
     * 
     */
    public GetHisPrivacyCAWebService2 createGetHisPrivacyCAWebService2() {
        return new GetHisPrivacyCAWebService2();
    }

    /**
     * Create an instance of {@link GetHisPrivacyCAWebService2Response }
     * 
     */
    public GetHisPrivacyCAWebService2Response createGetHisPrivacyCAWebService2Response() {
        return new GetHisPrivacyCAWebService2Response();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetHisPrivacyCAWebService2 }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", name = "getHisPrivacyCAWebService2")
    public JAXBElement<GetHisPrivacyCAWebService2> createGetHisPrivacyCAWebService2(GetHisPrivacyCAWebService2 value) {
        return new JAXBElement<GetHisPrivacyCAWebService2>(_GetHisPrivacyCAWebService2_QNAME, GetHisPrivacyCAWebService2 .class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetHisPrivacyCAWebService2Response }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", name = "getHisPrivacyCAWebService2Response")
    public JAXBElement<GetHisPrivacyCAWebService2Response> createGetHisPrivacyCAWebService2Response(GetHisPrivacyCAWebService2Response value) {
        return new JAXBElement<GetHisPrivacyCAWebService2Response>(_GetHisPrivacyCAWebService2Response_QNAME, GetHisPrivacyCAWebService2Response.class, null, value);
    }

}
