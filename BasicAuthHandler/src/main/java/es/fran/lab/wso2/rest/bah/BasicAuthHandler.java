/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package es.fran.lab.wso2.rest.bah;

import java.util.Map;
import org.apache.axis2.context.MessageContext;
import org.apache.commons.codec.binary.Base64;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;

/**
 *
 * @author fran
 */
public class BasicAuthHandler implements org.apache.synapse.rest.Handler {

    private static final String _USERNAME = "admin";
    private static final String _PASSWORD = "admin";

    /**************************************************************************/
    /*                       Metodos Privados                                 */
    /**************************************************************************/
    /**
     *
     * @param username
     * @param password
     * @return
     */
    private boolean _check(final String username, final String password) {
        return (_USERNAME.equals(username) && _PASSWORD.equals(password)) ? true : false;
    }

    /**
     *
     * @param credentials
     * @return
     */
    private boolean _check(final String credentials) {
        final String decodedCredentials = new String(new Base64().decode(credentials.getBytes()));

        final String username = decodedCredentials.split(":")[0];
        final String password = decodedCredentials.split(":")[1];

        return _check(username, password);
    }

    /**
     *
     * @param headers
     * @return
     */
    private String _getCredentials(final Map headers) {
        final String authorization;

        if ((authorization = (String) headers.get("Authorization")) == null) return null;

        return authorization.substring(6).trim();
    }

    /**
     *
     * @param mc
     */
    private void _setUnauthorized(final org.apache.synapse.MessageContext mc) {
        final MessageContext axis2mc = ((Axis2MessageContext) mc).getAxis2MessageContext();
        final Map            map     = (Map) axis2mc.getProperty(MessageContext.TRANSPORT_HEADERS);

        map.clear();
        map.put            ("WWW-Authenticate", "Basic realm=\"WSO2 ESB\"");
        axis2mc.setProperty("HTTP_SC", "401");
        axis2mc.setProperty("NO_ENTITY_BODY", Boolean.valueOf("true"));
        mc.setProperty     ("RESPONSE", "true");
        mc.setTo           (null);
    }

    /**
     *
     * @param mc
     */
    private void _setForbidden(final org.apache.synapse.MessageContext mc) {
        final MessageContext axis2mc = ((Axis2MessageContext) mc).getAxis2MessageContext();
        final Map            map     = (Map) axis2mc.getProperty(MessageContext.TRANSPORT_HEADERS);

        map.clear();
        axis2mc.setProperty("HTTP_SC", "403");
        axis2mc.setProperty("NO_ENTITY_BODY", new Boolean("true"));
        mc.setProperty     ("RESPONSE", "true");
        mc.setTo           (null);
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
     * @param mc
     * @return
     */
    @Override
    public boolean handleRequest(final org.apache.synapse.MessageContext mc) {
        final MessageContext axis2mc = ((Axis2MessageContext) mc).getAxis2MessageContext();
        final Object         headers = axis2mc.getProperty(MessageContext.TRANSPORT_HEADERS);

        //0.-
        if (headers                  == null)  return true;
        if ((headers instanceof Map) == false) return true;

        //1.- Get credentials for authorization header
         final String credentials = _getCredentials((Map) headers);

        //2.- No Authorization header
        if (credentials == null)
        {
            _setUnauthorized    (mc);
            Axis2Sender.sendBack(mc);

            return false;
        }

        //3.- Check credentials
        if (_check(credentials) == false)
        {
            _setForbidden       (mc);
            Axis2Sender.sendBack(mc);

            return false;
        }

        return true;
    }

    /**
     *
     * @param mc
     * @return
     */
    @Override
    public boolean handleResponse(final org.apache.synapse.MessageContext mc) {return true;}
}
