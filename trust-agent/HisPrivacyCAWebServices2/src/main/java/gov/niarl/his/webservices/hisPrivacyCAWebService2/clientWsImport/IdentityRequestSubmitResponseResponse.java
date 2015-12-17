
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for identityRequestSubmitResponseResponse complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="identityRequestSubmitResponseResponse">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="encryptedCertificate" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "identityRequestSubmitResponseResponse", propOrder = {
    "encryptedCertificate"
})
public class IdentityRequestSubmitResponseResponse {

    protected ByteArray encryptedCertificate;

    /**
     * Gets the value of the encryptedCertificate property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getEncryptedCertificate() {
        return encryptedCertificate;
    }

    /**
     * Sets the value of the encryptedCertificate property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setEncryptedCertificate(ByteArray value) {
        this.encryptedCertificate = value;
    }

}
