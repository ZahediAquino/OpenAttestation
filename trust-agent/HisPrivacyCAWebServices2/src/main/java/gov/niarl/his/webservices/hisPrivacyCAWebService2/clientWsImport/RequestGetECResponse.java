
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for requestGetECResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="requestGetECResponse">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="requestGetEC" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "requestGetECResponse", propOrder = {
    "requestGetEC"
})
public class RequestGetECResponse {

    protected ByteArray requestGetEC;

    /**
     * Gets the value of the requestGetEC property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getRequestGetEC() {
        return requestGetEC;
    }

    /**
     * Sets the value of the requestGetEC property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setRequestGetEC(ByteArray value) {
        this.requestGetEC = value;
    }

}
