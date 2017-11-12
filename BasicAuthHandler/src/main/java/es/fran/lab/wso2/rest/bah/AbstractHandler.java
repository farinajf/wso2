/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package es.fran.lab.wso2.rest.bah;

import java.util.HashMap;
import java.util.Map;
import org.apache.synapse.rest.Handler;

/**
 *
 * @author fran
 */
public abstract class AbstractHandler implements Handler {

    protected final Map<String, Object> properties = new HashMap<String, Object>();

    public void addProperty(String name, Object value) {properties.put(name, value);}

    public Map getProperties() {return properties;}
}
