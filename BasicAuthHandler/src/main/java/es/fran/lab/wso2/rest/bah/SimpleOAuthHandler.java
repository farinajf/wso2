/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package es.fran.lab.wso2.rest.bah;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.SynapseEnvironment;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;

/**
 *
 * @author fran
 */
public class SimpleOAuthHandler extends AbstractHandler implements ManagedLifecycle {
    private static final Log    _log                = LogFactory.getLog(SimpleOAuthHandler.class);
    private static final String _OAUTH_TOKEN_VALIDATOR_SERVER = "oauth2TokenValidationService";
    private static final String _IDP_LOGIN_USERNAME           = "identityServerUserName";
    private static final String _IDP_LOGIN_PASSWORD           = "identityServerPw";

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
        return null;
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
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void destroy() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
