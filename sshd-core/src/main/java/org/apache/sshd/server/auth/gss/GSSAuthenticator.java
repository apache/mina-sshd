/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.auth.gss;

import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.security.auth.login.LoginException;

import org.apache.sshd.server.session.ServerSession;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;

/**
 * Class providing basic GSS authentication services. Can be used as-is, but is often extended to provide environment
 * specific implementations.
 *
 * @author Richard Evans
 */

public class GSSAuthenticator {
    // Options:
    //
    // Service principal name: if unset, use host/hostname
    private String servicePrincipalName;

    // Location of Kerberos key table; if unset use default
    private String keytabFile;

    public GSSAuthenticator() {
        super();
    }

    /**
     * Overridable method to get GSS manager suitable for current environment.
     *
     * @return A new manager
     */
    public GSSManager getGSSManager() {
        return GSSManager.getInstance();
    }

    /**
     * Overridable method to get GSS accept credential suitable for the current environment. The default implementation
     * uses a Kerberos key table.
     *
     * @param  mgr                  The GSS manager
     * @return                      The credential; if the result is {@code null} gssapi authentication fails
     *                              immediately
     * @throws UnknownHostException If the local host name could not be determined
     * @throws LoginException       If the subject could not be found
     * @throws GSSException         If the credential could not be obtained
     */
    public GSSCredential getGSSCredential(GSSManager mgr) throws UnknownHostException, LoginException, GSSException {
        String name = servicePrincipalName;
        if (name == null) {
            name = "host/" + InetAddress.getLocalHost().getCanonicalHostName();
        }

        return CredentialHelper.creds(mgr, name, keytabFile);
    }

    /**
     * Validate the user name passed in the initial SSH_MSG_USERAUTH_REQUEST message. This is sort of mandated by RFC
     * 4462, but it may be more useful to wait for the GSS negotiation to complete. The default implementation here
     * always succeeds.
     *
     * @param  session The current session
     * @param  user    The user name from the initial request
     * @return         <code>true</code> if the user is valid, <code>false</code> if invalid
     */
    public boolean validateInitialUser(ServerSession session, String user) {
        return true;
    }

    /**
     * Validate the source identity obtained from the context after negotiation is complete. The default implementation
     * here always succeeds.
     *
     * @param  session  The current session
     * @param  identity The identity from the GSS context
     * @return          <code>true</code> if the identity is valid, <code>false</code> if invalid
     */
    public boolean validateIdentity(ServerSession session, String identity) {
        return true;
    }

    /**
     * Set the service principal name to be used. The default is host/hostname.
     *
     * @param servicePrincipalName The principal name
     */
    public void setServicePrincipalName(String servicePrincipalName) {
        this.servicePrincipalName = servicePrincipalName;
    }

    /**
     * Set the location of the Kerberos keytab. The default is defined by the JRE.
     *
     * @param keytabFile The location of the keytab
     */
    public void setKeytabFile(String keytabFile) {
        this.keytabFile = keytabFile;
    }
}
