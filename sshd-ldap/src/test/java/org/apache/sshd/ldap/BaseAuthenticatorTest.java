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

import java.util.Comparator;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Category({ NoIoTestCase.class })
public abstract class BaseAuthenticatorTest extends BaseTestSupport {

    public static final String BASE_DN_TEST = "ou=People,dc=sshd,dc=apache,dc=org";

    protected BaseAuthenticatorTest() {
        super();
    }

    public static String getHost(Map.Entry<LdapServer, DirectoryService> context) {
        return getHost((context == null) ? null : context.getKey());
    }

    public static String getHost(LdapServer ldapServer) {
        return getHost((ldapServer == null) ? null : ldapServer.getTransports());
    }

    public static String getHost(Transport... transports) {
        return GenericUtils.isEmpty(transports) ? null : transports[0].getAddress();
    }

    public static int getPort(Map.Entry<LdapServer, DirectoryService> context) {
        return getPort((context == null) ? null : context.getKey());
    }

    public static int getPort(LdapServer ldapServer) {
        return getPort((ldapServer == null) ? null : ldapServer.getTransports());
    }

    public static int getPort(Transport... transports) {
        return GenericUtils.isEmpty(transports) ? -1 : transports[0].getPort();
    }

    // see http://users.directory.apache.narkive.com/GkyqAkot/how-to-import-ldif-file-programmatically
    public static NavigableMap<String, String> populateUsers(DirectoryService service, Class<?> anchor, String credentialName)
            throws Exception {
        Logger log = LoggerFactory.getLogger(anchor);
        NavigableMap<String, String> usersMap = new TreeMap<>(Comparator.naturalOrder());
        try (LdifReader reader
                = new LdifReader(Objects.requireNonNull(anchor.getResourceAsStream("/auth-users.ldif"), "No users ldif"))) {
            for (LdifEntry entry : reader) {
                if (log.isDebugEnabled()) {
                    log.debug("Process LDIF entry={}", entry);
                }

                Entry data = entry.getEntry();
                Attribute userAttr = data.get("uid");
                Attribute passAttr = data.get(credentialName);
                if ((userAttr != null) && (passAttr != null)) {
                    String username = userAttr.getString();
                    ValidateUtils.checkTrue(usersMap.put(username, passAttr.getString()) == null,
                            "Multiple entries for user=%s", username);
                }
            }
        }

        return usersMap;
    }

}
