
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for identityRequestGetChallenge complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="identityRequestGetChallenge">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="identityRequest" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *         &lt;element name="endorsementCertificate" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "identityRequestGetChallenge", propOrder = {
    "identityRequest",
    "endorsementCertificate"
})
public class IdentityRequestGetChallenge {

    protected ByteArray identityRequest;
    protected ByteArray endorsementCertificate;

    /**
     * Gets the value of the identityRequest property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getIdentityRequest() {
        return identityRequest;
    }

    /**
     * Sets the value of the identityRequest property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setIdentityRequest(ByteArray value) {
        this.identityRequest = value;
    }

    /**
     * Gets the value of the endorsementCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getEndorsementCertificate() {
        return endorsementCertificate;
    }

    /**
     * Sets the value of the endorsementCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setEndorsementCertificate(ByteArray value) {
        this.endorsementCertificate = value;
    }

}
