
package gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Logger;
import javax.xml.namespace.QName;
import javax.xml.ws.Service;
import javax.xml.ws.WebEndpoint;
import javax.xml.ws.WebServiceClient;
import javax.xml.ws.WebServiceFeature;


/**
 * This class was generated by the JAX-WS RI.
 * JAX-WS RI 2.1.7-b01-
 * Generated source version: 2.1
 * 
 */
@WebServiceClient(name = "HisPrivacyCAWebService2FactoryServiceService", targetNamespace = "http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", wsdlLocation = "file:/C:/DCG_OAT/repo/oat-internal/trust-agent/HisPrivacyCAWebServices2/src/main/resources/hisPrivacyCAWebService2FactoryService.wsdl")
public class HisPrivacyCAWebService2FactoryServiceService
    extends Service
{

    private final static URL HISPRIVACYCAWEBSERVICE2FACTORYSERVICESERVICE_WSDL_LOCATION;
    private final static Logger logger = Logger.getLogger(gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport.HisPrivacyCAWebService2FactoryServiceService.class.getName());

    static {
        URL url = null;
        try {
            URL baseUrl;
            baseUrl = gov.niarl.his.webservices.hisPrivacyCAWebServices2.clientWsImport.HisPrivacyCAWebService2FactoryServiceService.class.getResource(".");
            url = new URL(baseUrl, "file:/C:/DCG_OAT/repo/oat-internal/trust-agent/HisPrivacyCAWebServices2/src/main/resources/hisPrivacyCAWebService2FactoryService.wsdl");
        } catch (MalformedURLException e) {
            logger.warning("Failed to create URL for the wsdl Location: 'file:/C:/DCG_OAT/repo/oat-internal/trust-agent/HisPrivacyCAWebServices2/src/main/resources/hisPrivacyCAWebService2FactoryService.wsdl', retrying as a local file");
            logger.warning(e.getMessage());
        }
        HISPRIVACYCAWEBSERVICE2FACTORYSERVICESERVICE_WSDL_LOCATION = url;
    }

    public HisPrivacyCAWebService2FactoryServiceService(URL wsdlLocation, QName serviceName) {
        super(wsdlLocation, serviceName);
    }

    public HisPrivacyCAWebService2FactoryServiceService() {
        super(HISPRIVACYCAWEBSERVICE2FACTORYSERVICESERVICE_WSDL_LOCATION, new QName("http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", "HisPrivacyCAWebService2FactoryServiceService"));
    }

    /**
     * 
     * @return
     *     returns HisPrivacyCAWebService2FactoryService
     */
    @WebEndpoint(name = "HisPrivacyCAWebService2FactoryServicePort")
    public HisPrivacyCAWebService2FactoryService getHisPrivacyCAWebService2FactoryServicePort() {
        return super.getPort(new QName("http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", "HisPrivacyCAWebService2FactoryServicePort"), HisPrivacyCAWebService2FactoryService.class);
    }

    /**
     * 
     * @param features
     *     A list of {@link javax.xml.ws.WebServiceFeature} to configure on the proxy.  Supported features not in the <code>features</code> parameter will have their default values.
     * @return
     *     returns HisPrivacyCAWebService2FactoryService
     */
    @WebEndpoint(name = "HisPrivacyCAWebService2FactoryServicePort")
    public HisPrivacyCAWebService2FactoryService getHisPrivacyCAWebService2FactoryServicePort(WebServiceFeature... features) {
        return super.getPort(new QName("http://server.hisPrivacyCAWebService2.webservices.his.niarl.gov/", "HisPrivacyCAWebService2FactoryServicePort"), HisPrivacyCAWebService2FactoryService.class, features);
    }

}
