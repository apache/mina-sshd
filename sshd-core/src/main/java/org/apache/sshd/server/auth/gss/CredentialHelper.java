/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.auth.gss;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;

/**
 * Simple helper class which gets GSS credential using a fixed Krb5 login configuration.  May need generalizing to deal
 * with non-Sun JREs.
 */

public class CredentialHelper {
  
  public static GSSCredential creds(GSSManager mgr, String spn, String keytab) throws LoginException, GSSException {
    LoginContext lc = new LoginContext("x", null, null, new FixedLoginConfiguration(spn, keytab));         
    
    lc.login();
            
    try {
      return (GSSCredential) Subject.doAs(lc.getSubject(), new G(mgr));
    } catch (PrivilegedActionException e) {
      throw (GSSException) e.getCause();
    }
  }
  
  /**
   * A login configuration which is defined from code.
   *
   * @author Richard Evans
   */

  private static class FixedLoginConfiguration extends Configuration {
    
    private AppConfigurationEntry entry;
    
    /**
     * Constructor.
     */
    
    private FixedLoginConfiguration(String spn, String keytab) {
      Map<String, String> parms = new HashMap<String, String>();
      
      parms.put("isInitiator", "false");
      parms.put("principal",   spn);
      parms.put("useKeyTab",   "true");
      parms.put("storeKey",    "true");
      
      if (keytab != null) {
        parms.put("keyTab", keytab);
      }
      
      entry = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, parms);
    }
    
    /**
     * Get the configuration entries for a name.
     * 
     * @param name The name
     * 
     * @return The entries, or <code>null</code> if the name is not known
     */
    
    public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
      return new AppConfigurationEntry [] { entry };
    }

    /**
     * Refresh the configuration.  Nothing to do here.
     */
    
    public void refresh() {    
    }
  }
  
  /**
   * Privileged action which runs as the subject to get the credentials.
   */

  private static final class G implements PrivilegedExceptionAction<GSSCredential> {
    
    private GSSManager mgr;
    
    /**
     * @param mgr The existing GSS manager
     */
    
    private G(GSSManager mgr) {
      this.mgr      = mgr;
    }
    
    /**
     * Do the action.
     * 
     * @return The new credentials
     * 
     * @throws GSSException If an error occurred
     */
    
    public GSSCredential run() throws GSSException {
      return mgr.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, UserAuthGSS.KRB5_MECH, GSSCredential.ACCEPT_ONLY);      
    }
  }
}
