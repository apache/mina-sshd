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

package org.apache.sshd.ldap;

import java.util.Map;

import javax.naming.NamingException;

import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException;
import org.apache.sshd.server.session.ServerSession;

/**
 * Uses LDAP to authenticate a user and password. By default it can achieve this using 2 ways:
 * <OL>
 * <P>
 * <LI>Comparing the provided password with the one stored in LDAP. In this case, the bind DN and password patterns can
 * be either empty (if anonymous access allowed) or can contain the administrative username / password required to run
 * the LDAP query. The search filter pattern should be set to require a match for <U>both</U> the username and password
 * - e.g., <code>&quot;(&(user={0})(password={1}))&quot;</code>. The set default
 * ({@link #DEFAULT_SEARCH_FILTER_PATTERN}) uses the most commonly encountered attributes names for this purpose.</LI>
 * </P>
 *
 * <P>
 * <LI>Using the original username + password to access LDAP - in which case the very success of retrieving anything can
 * be considered a successful authentication. In this case, the bind DN and password patterns should be set up to
 * generate the correct credentials - the default is to &quot;echo&quot; the provided username and password as-is. E.g.,
 * if the username is always the alias part of a known e-mail, the bind DN should be set to
 * <code>&quot;{0}@my.domain.com&quot;</code>.</LI>
 * </P>
 * </OL>
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LdapPasswordAuthenticator extends LdapAuthenticator implements PasswordAuthenticator {
    public static final String DEFAULT_PASSWORD_ATTR_NAME = "userPassword";

    public static final String DEFAULT_SEARCH_FILTER_PATTERN
            = "(&(" + DEFAULT_USERNAME_ATTR_NAME + "={0})(" + DEFAULT_PASSWORD_ATTR_NAME + "={1}))";

    public LdapPasswordAuthenticator() {
        setRetrievedAttributes(null);
        setSearchFilterPattern(DEFAULT_SEARCH_FILTER_PATTERN);
    }

    @Override
    public boolean authenticate(String username, String password, ServerSession session)
            throws PasswordChangeRequiredException {
        try {
            Map<String, ?> attrs = resolveAttributes(username, password, session);
            return authenticate(username, password, session, attrs);
        } catch (NamingException | RuntimeException e) {
            warn("authenticate({}@{}) failed ({}) to query: {}",
                    username, session, e.getClass().getSimpleName(), e.getMessage(), e);
            return false;
        }
    }

    protected boolean authenticate(
            String username, String password, ServerSession session, Map<String, ?> attrs) {
        /*
         * By default we assume that the user + password are the same for accessing the LDAP as the user's account, so
         * the very LDAP query success is enough
         */
        return true;
    }
}
