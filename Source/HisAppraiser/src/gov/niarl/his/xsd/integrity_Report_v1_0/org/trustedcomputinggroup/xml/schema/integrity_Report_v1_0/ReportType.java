//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-793 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2009.07.27 at 03:47:01 PM EDT 
//


package gov.niarl.his.xsd.integrity_Report_v1_0.org.trustedcomputinggroup.xml.schema.integrity_Report_v1_0;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlID;
import javax.xml.bind.annotation.XmlIDREF;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import gov.niarl.his.xsd.integrity_Report_v1_0.org.trustedcomputinggroup.xml.schema.core_Integrity_v1_0_1.ConfidenceValueType;
import gov.niarl.his.xsd.integrity_Report_v1_0.org.trustedcomputinggroup.xml.schema.core_Integrity_v1_0_1.SignerInfoType;


/**
 * <p>Java class for ReportType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ReportType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="SignerInfo" type="{http://www.trustedcomputinggroup.org/XML/SCHEMA/Core_Integrity_v1_0_1#}SignerInfoType" minOccurs="0"/>
 *         &lt;element name="ConfidenceValue" type="{http://www.trustedcomputinggroup.org/XML/SCHEMA/Core_Integrity_v1_0_1#}ConfidenceValueType" minOccurs="0"/>
 *         &lt;element name="QuoteData" type="{http://www.trustedcomputinggroup.org/XML/SCHEMA/Integrity_Report_v1_0#}QuoteDataType" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="SnapshotCollection" type="{http://www.trustedcomputinggroup.org/XML/SCHEMA/Integrity_Report_v1_0#}SnapshotType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ID" use="required" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *       &lt;attribute name="UUID" use="required" type="{http://www.w3.org/2001/XMLSchema}NMTOKEN" />
 *       &lt;attribute name="SyncSnapshotRefs" type="{http://www.w3.org/2001/XMLSchema}IDREFS" />
 *       &lt;attribute name="TransitiveTrustPath" type="{http://www.w3.org/2001/XMLSchema}IDREFS" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ReportType", propOrder = {
    "signerInfo",
    "confidenceValue",
    "quoteData",
    "snapshotCollection"
})
public class ReportType {

    @XmlElement(name = "SignerInfo")
    protected SignerInfoType signerInfo;
    @XmlElement(name = "ConfidenceValue")
    protected ConfidenceValueType confidenceValue;
    @XmlElement(name = "QuoteData")
    protected List<QuoteDataType> quoteData;
    @XmlElement(name = "SnapshotCollection", required = true)
    protected List<SnapshotType> snapshotCollection;
    @XmlAttribute(name = "ID", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String id;
    @XmlAttribute(name = "UUID", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "NMTOKEN")
    protected String uuid;
    @XmlAttribute(name = "SyncSnapshotRefs")
    @XmlIDREF
    @XmlSchemaType(name = "IDREFS")
    protected List<Object> syncSnapshotRefs;
    @XmlAttribute(name = "TransitiveTrustPath")
    @XmlIDREF
    @XmlSchemaType(name = "IDREFS")
    protected List<Object> transitiveTrustPath;

    /**
     * Gets the value of the signerInfo property.
     * 
     * @return
     *     possible object is
     *     {@link SignerInfoType }
     *     
     */
    public SignerInfoType getSignerInfo() {
        return signerInfo;
    }

    /**
     * Sets the value of the signerInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignerInfoType }
     *     
     */
    public void setSignerInfo(SignerInfoType value) {
        this.signerInfo = value;
    }

    /**
     * Gets the value of the confidenceValue property.
     * 
     * @return
     *     possible object is
     *     {@link ConfidenceValueType }
     *     
     */
    public ConfidenceValueType getConfidenceValue() {
        return confidenceValue;
    }

    /**
     * Sets the value of the confidenceValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link ConfidenceValueType }
     *     
     */
    public void setConfidenceValue(ConfidenceValueType value) {
        this.confidenceValue = value;
    }

    /**
     * Gets the value of the quoteData property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the quoteData property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getQuoteData().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link QuoteDataType }
     * 
     * 
     */
    public List<QuoteDataType> getQuoteData() {
        if (quoteData == null) {
            quoteData = new ArrayList<QuoteDataType>();
        }
        return this.quoteData;
    }

    /**
     * Gets the value of the snapshotCollection property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the snapshotCollection property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSnapshotCollection().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link SnapshotType }
     * 
     * 
     */
    public List<SnapshotType> getSnapshotCollection() {
        if (snapshotCollection == null) {
            snapshotCollection = new ArrayList<SnapshotType>();
        }
        return this.snapshotCollection;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getID() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setID(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the uuid property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUUID() {
        return uuid;
    }

    /**
     * Sets the value of the uuid property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUUID(String value) {
        this.uuid = value;
    }

    /**
     * Gets the value of the syncSnapshotRefs property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the syncSnapshotRefs property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSyncSnapshotRefs().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Object }
     * 
     * 
     */
    public List<Object> getSyncSnapshotRefs() {
        if (syncSnapshotRefs == null) {
            syncSnapshotRefs = new ArrayList<Object>();
        }
        return this.syncSnapshotRefs;
    }

    /**
     * Gets the value of the transitiveTrustPath property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the transitiveTrustPath property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTransitiveTrustPath().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Object }
     * 
     * 
     */
    public List<Object> getTransitiveTrustPath() {
        if (transitiveTrustPath == null) {
            transitiveTrustPath = new ArrayList<Object>();
        }
        return this.transitiveTrustPath;
    }

}
