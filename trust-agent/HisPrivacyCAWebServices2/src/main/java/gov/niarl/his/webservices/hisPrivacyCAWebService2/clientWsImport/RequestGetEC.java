
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for requestGetEC complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="requestGetEC">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="encryptedEkMod" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *         &lt;element name="arg1" type="{http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/}byteArray" minOccurs="0"/>
 *         &lt;element name="arg2" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "requestGetEC", propOrder = {
    "encryptedEkMod",
    "arg1",
    "arg2"
})
public class RequestGetEC {

    protected ByteArray encryptedEkMod;
    protected ByteArray arg1;
    protected int arg2;

    /**
     * Gets the value of the encryptedEkMod property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getEncryptedEkMod() {
        return encryptedEkMod;
    }

    /**
     * Sets the value of the encryptedEkMod property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setEncryptedEkMod(ByteArray value) {
        this.encryptedEkMod = value;
    }

    /**
     * Gets the value of the arg1 property.
     * 
     * @return
     *     possible object is
     *     {@link ByteArray }
     *     
     */
    public ByteArray getArg1() {
        return arg1;
    }

    /**
     * Sets the value of the arg1 property.
     * 
     * @param value
     *     allowed object is
     *     {@link ByteArray }
     *     
     */
    public void setArg1(ByteArray value) {
        this.arg1 = value;
    }

    /**
     * Gets the value of the arg2 property.
     * 
     */
    public int getArg2() {
        return arg2;
    }

    /**
     * Sets the value of the arg2 property.
     * 
     */
    public void setArg2(int value) {
        this.arg2 = value;
    }

}
