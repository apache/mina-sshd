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

package org.apache.sshd.server.auth.password;

import java.util.Map;

import javax.naming.NamingException;

import org.apache.sshd.common.util.net.LdapNetworkConnector;
import org.apache.sshd.server.session.ServerSession;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LdapPasswordAuthenticator extends LdapNetworkConnector implements PasswordAuthenticator {
    public static final String DEFAULT_USERNAME_ATTR_NAME = "uid";
    public static final String DEFAULT_PASSWORD_ATTR_NAME = "userPassword";

    public static final String DEFAULT_SEARCH_FILTER_PATTERN =
            "(&(" + DEFAULT_USERNAME_ATTR_NAME + "={0})(" + DEFAULT_PASSWORD_ATTR_NAME + "={1}))";
    public static final String DEFAULT_AUTHENTICATION_MODE = "none";

    public LdapPasswordAuthenticator() {
        setRetrievedAttributes(null);
        setAuthenticationMode(DEFAULT_AUTHENTICATION_MODE);
        setSearchFilterPattern(DEFAULT_SEARCH_FILTER_PATTERN);
    }

    @Override
    public boolean authenticate(String username, String password, ServerSession session) throws PasswordChangeRequiredException {
        try {
            Map<String, ?> attrs = resolveAttributes(username, password, session);
            return authenticate(username, password, session, attrs);
        } catch (NamingException | RuntimeException e) {
            log.warn("authenticate({}@{}) failed ({}) to query: {}",
                      username, session, e.getClass().getSimpleName(), e.getMessage());

            if (log.isDebugEnabled()) {
                log.debug("authenticate(" + username + "@" + session + ") query failure details", e);
            }

            return false;
        }
    }

    protected boolean authenticate(String username, String password, ServerSession session, Map<String, ?> attrs) {
        /*
         * By default we assume that the user + password are the same for
         * accessing the LDAP as the user's account, so the very LDAP query
         * success is enough
         */
        return true;
    }
}
