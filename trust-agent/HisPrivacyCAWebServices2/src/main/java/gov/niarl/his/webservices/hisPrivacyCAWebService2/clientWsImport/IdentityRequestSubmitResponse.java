
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for identityRequestSubmitResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="identityRequestSubmitResponse">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="identityRequestResponseToChallenge" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "identityRequestSubmitResponse", propOrder = {
    "identityRequestResponseToChallenge"
})
public class IdentityRequestSubmitResponse {

    protected ByteArray identityRequestResponseToChallenge;

    /**
     * Gets the value of the identityRequestResponseToChallenge property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getIdentityRequestResponseToChallenge() {
        return identityRequestResponseToChallenge;
    }

    /**
     * Sets the value of the identityRequestResponseToChallenge property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setIdentityRequestResponseToChallenge(ByteArray value) {
        this.identityRequestResponseToChallenge = value;
    }

}
