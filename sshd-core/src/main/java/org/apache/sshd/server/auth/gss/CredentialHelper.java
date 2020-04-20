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

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.TreeMap;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;

/**
 * Simple helper class which gets GSS credential using a fixed Krb5 login configuration. May need generalizing to deal
 * with non-Sun JREs.
 */
public final class CredentialHelper {

    private CredentialHelper() {
        throw new UnsupportedOperationException("No instance");
    }

    @SuppressWarnings("synthetic-access")
    public static GSSCredential creds(GSSManager mgr, String spn, String keytab) throws LoginException, GSSException {
        LoginContext lc = new LoginContext("x", null, null, new FixedLoginConfiguration(spn, keytab));
        lc.login();

        try {
            return Subject.doAs(lc.getSubject(), new G(mgr));
        } catch (PrivilegedActionException e) {
            throw (GSSException) e.getCause();
        }
    }

    /**
     * A login configuration which is defined from code.
     *
     * @author Richard Evans
     */
    private static final class FixedLoginConfiguration extends Configuration {

        private AppConfigurationEntry entry;

        private FixedLoginConfiguration(String spn, String keytab) {
            Map<String, String> params = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            params.put("isInitiator", "false");
            params.put("principal", spn);
            params.put("useKeyTab", "true");
            params.put("storeKey", "true");

            if (keytab != null) {
                params.put("keyTab", keytab);
            }

            entry = new AppConfigurationEntry(
                    "com.sun.security.auth.module.Krb5LoginModule", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    params);
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            return new AppConfigurationEntry[] { entry };
        }

        @Override
        public void refresh() {
            // ignored
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
            this.mgr = mgr;
        }

        @Override
        public GSSCredential run() throws GSSException {
            return mgr.createCredential(null, GSSCredential.INDEFINITE_LIFETIME, UserAuthGSS.KRB5_MECH,
                    GSSCredential.ACCEPT_ONLY);
        }
    }
}
