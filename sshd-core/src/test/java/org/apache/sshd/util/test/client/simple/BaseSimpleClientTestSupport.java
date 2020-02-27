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

package org.apache.sshd.util.test.client.simple;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.simple.SimpleClient;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.After;
import org.junit.Before;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class BaseSimpleClientTestSupport extends BaseTestSupport {

    protected SshServer sshd;
    protected SshClient client;
    protected int port;
    protected SimpleClient simple;

    protected BaseSimpleClientTestSupport() {
        super();
    }

    @Before
    public void setUp() throws Exception {
        sshd = setupTestServer();
        sshd.start();
        port = sshd.getPort();
        client = setupTestClient();

        simple = SshClient.wrapAsSimpleClient(client);
        simple.setConnectTimeout(CONNECT_TIMEOUT.toMillis());
        simple.setAuthenticationTimeout(AUTH_TIMEOUT.toMillis());
    }

    @After
    public void tearDown() throws Exception {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (simple != null) {
            simple.close();
        }
        if (client != null) {
            client.stop();
        }
    }
}
