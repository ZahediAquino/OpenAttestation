
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for identityRequestGetChallengeResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="identityRequestGetChallengeResponse">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="identityRequestChallenge" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "identityRequestGetChallengeResponse", propOrder = {
    "identityRequestChallenge"
})
public class IdentityRequestGetChallengeResponse {

    protected ByteArray identityRequestChallenge;

    /**
     * Gets the value of the identityRequestChallenge property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getIdentityRequestChallenge() {
        return identityRequestChallenge;
    }

    /**
     * Sets the value of the identityRequestChallenge property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setIdentityRequestChallenge(ByteArray value) {
        this.identityRequestChallenge = value;
    }

}
