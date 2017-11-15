/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package es.fran.lab.wso2.rest.bah;

import java.util.Map;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;

/**
 *
 * @author fran
 */
public class SimpleOAuthHandler extends AbstractHandler implements ManagedLifecycle {
    private static final Log    _log                = LogFactory.getLog(SimpleOAuthHandler.class);
    private static final String _OAUTH_TOKEN_VALIDATOR_SERVER   = "oauth2TokenValidationService";
    private static final String _OAUTH_HEADER_SPLITER           = ",";
    private static final String _CONSUMER_KEY_HEADER            = "Bearer";
    private static final String _CONSUMER_KEY_SEGMENT_DELIMITER = " ";
    private static final String _IDP_LOGIN_USERNAME             = "identityServerUserName";
    private static final String _IDP_LOGIN_PASSWORD             = "identityServerPw";

    private ConfigurationContext _configContext;

    /**************************************************************************/
    /*                       Metodos Privados                                 */
    /**************************************************************************/
    /**
     *
     * @return
     */
    private ConfigurationContext _getConfigContext() {return _configContext;}

    /**
     *
     * @param m
     * @return
     */
    private String _getUsername(final MessageContext m) {
        return m.getConfiguration().getAxisConfiguration().getParameter(_IDP_LOGIN_USERNAME).getValue().toString();
    }

    private String _getPassword(final MessageContext m) {
        return m.getConfiguration().getAxisConfiguration().getParameter(_IDP_LOGIN_PASSWORD).getValue().toString();
    }

    /**
     *
     * @param m
     * @return
     */
    private OAuth2TokenValidationServiceStub _getStub(final MessageContext m) throws AxisFault {
        final String isurl = m.getConfiguration().getAxisConfiguration().getParameter(_OAUTH_TOKEN_VALIDATOR_SERVER).getValue().toString();

        return new OAuth2TokenValidationServiceStub(_configContext, isurl);
    }

    /**
     *
     * @param m
     * @return
     */
    private OAuth2TokenValidationRequestDTO _createOAuthValidatorDTO(final MessageContext m) {
        OAuth2TokenValidationRequestDTO result = new OAuth2TokenValidationRequestDTO();

        Map headers = (Map) ((Axis2MessageContext) m).getAxis2MessageContext().getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        final String key = (headers != null) ? _extractKey(headers) : null;

        OAuth2TokenValidationRequestDTO_OAuth2AccessToken token = new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();

        token.setTokenType ("bearer");
        token.setIdentifier(key);

        result.setAccessToken(token);

        return result;
    }

    /**
     *
     * @param headers
     * @return
     */
    private String _extractKey(final Map headers) {
        String authHeader;

        if ((authHeader = (String) headers.get(HttpHeaders.AUTHORIZATION)) == null) return null;

        if (authHeader.startsWith("OAuth ") || authHeader.startsWith("oauth "))
        {
            authHeader = authHeader.substring(authHeader.indexOf("o"));
        }

        String[] h = authHeader.split(_OAUTH_HEADER_SPLITER);

        if (h != null)
        {
            for (String header : h)
            {
                String[] elements = header.split(_CONSUMER_KEY_SEGMENT_DELIMITER);
                if (elements != null && elements.length > 1)
                {
                    boolean isConsumerKeyAvailable = false;

                    for (String element : elements)
                    {
                        if (!"".equals(element.trim()))
                        {
                            if (_CONSUMER_KEY_HEADER.equals(element.trim())) isConsumerKeyAvailable = true;
                            else if (isConsumerKeyAvailable) return _removeLeadingAndTrailing(element.trim());
                        }
                    }
                }
            }
        }

        return null;
    }

    private String _removeLeadingAndTrailing(final String s) {
        String result = s;

        if (s.startsWith("\"") || s.endsWith("\"")) result = s.replace("\"", "");

        return result.trim();
    }

    /**************************************************************************/
    /*                       Metodos Protegidos                               */
    /**************************************************************************/

    /**************************************************************************/
    /*                          Constructores                                 */
    /**************************************************************************/

    /**************************************************************************/
    /*                       Metodos Publicos                                 */
    /**************************************************************************/
    /**
     *
     * @param messageContext
     * @return
     */
    @Override
    public boolean handleRequest(MessageContext messageContext) {
        if (_getConfigContext() == null)
        {
            _log.error("Configuration context null!!");
            return false;
        }

        try
        {
            final String                           username = _getUsername(messageContext);
            final String                           password = _getPassword(messageContext);
            final OAuth2TokenValidationServiceStub stub     = _getStub    (messageContext);
            final ServiceClient                    client   = stub._getServiceClient();
            final Options                          options  = client.getOptions();

            final HttpTransportProperties.ProxyProperties authenticator = new HttpTransportProperties.ProxyProperties();
            authenticator.setUserName(username);
            authenticator.setPassWord(password);

            options.setProperty(HTTPConstants.AUTHENTICATE, authenticator);

            client.setOptions(options);

            OAuth2TokenValidationRequestDTO dto = _createOAuthValidatorDTO(messageContext);

            return stub.validate(dto).getValid();
        }
        catch (Exception e)
        {
            _log.error("ERROR processing message!!", e);
            return false;
        }
    }

    @Override
    public boolean handleResponse(MessageContext messageContext) {return true;}

    @Override
    public void init(SynapseEnvironment se) {
        try
        {
            _configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
        }
        catch (AxisFault e)
        {
            _log.error("Error initializing configuration context!!", e);
        }
    }

    @Override
    public void destroy() {
        _configContext = null;
    }
}
