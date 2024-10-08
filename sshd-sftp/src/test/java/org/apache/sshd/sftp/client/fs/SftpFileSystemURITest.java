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

package org.apache.sshd.sftp.client.fs;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.BasicCredentialsProvider;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.sftp.common.SftpConstants;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class SftpFileSystemURITest extends JUnitTestSupport {
    private String host;
    private int port;
    private String username;
    private String password;
    private Map<String, ?> params;

    public void initSftpFileSystemURITest(String host, int port, String username, String password, Map<String, ?> params) {
        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
        this.params = params;
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                add(new Object[] { SshdSocketAddress.LOCALHOST_NAME, 0, "user", "password", null });
                add(new Object[] {
                        "37.77.34.7", 2222, "user", "password", Collections.singletonMap("non-default-port", true) });
                add(new Object[] {
                        SshdSocketAddress.LOCALHOST_NAME, SshConstants.DEFAULT_PORT, "J@ck", "d@Ripper",
                        new HashMap<String, Object>() {
                            // not serializing it
                            private static final long serialVersionUID = 1L;

                            {
                                put("param1", "1st");
                                put("param2", 2);
                                put("param3", false);
                            }
                        }
                });
                add(new Object[] { "19.65.7.3", 0, "J%ck", "d%Ripper", null });
                add(new Object[] { "19.65.7.3", 0, "user", null, null });
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "host={0}, port={1}, user={2}, password={3}, params={4}")
    public void fullURIEncoding(String host, int port, String username, String password, Map<String, ?> params) {
        initSftpFileSystemURITest(host, port, username, password, params);
        URI uri = SftpFileSystemProvider.createFileSystemURI(host, port, username, password, params);
        assertEquals(SftpConstants.SFTP_SUBSYSTEM_NAME, uri.getScheme(), "Mismatched scheme");
        assertEquals(host, uri.getHost(), "Mismatched host");
        assertEquals(port, uri.getPort(), "Mismatched port");

        BasicCredentialsProvider credentials = SftpFileSystemProvider.parseCredentials(uri);
        assertNotNull(credentials, "No credentials provided");
        assertEquals(username, credentials.getUsername(), "Mismatched user");
        assertEquals(password, credentials.getPassword(), "Mismatched password");

        Map<String, ?> uriParams = SftpFileSystemProvider.parseURIParameters(uri);
        assertMapEquals(getCurrentTestName(), params, uriParams, (v1, v2) -> Objects.equals(v1.toString(), v2.toString()));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "host={0}, port={1}, user={2}, password={3}, params={4}")
    public void encodeDecodeCredentials(String host, int port, String username, String password, Map<String, ?> params) {
        initSftpFileSystemURITest(host, port, username, password, params);
        String userInfo = SftpFileSystemProvider.encodeCredentials(username, password);
        BasicCredentialsProvider credentials = SftpFileSystemProvider.parseCredentials(userInfo);
        assertNotNull(credentials, "No credentials provided");
        assertEquals(username, credentials.getUsername(), "Mismatched user");
        assertEquals(password, credentials.getPassword(), "Mismatched password");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[host=" + host
               + ", port=" + port
               + ", username=" + username
               + ", password=" + password
               + ", params=" + params
               + "]";
    }
}
