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
package org.apache.sshd;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

import org.junit.*;
import org.hamcrest.*;

import org.apache.sshd.agent.AgentClient;
import org.apache.sshd.agent.AgentServer;
import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

public class AgentTest {

    @Test
    public void testAgent() throws Exception {
        AgentServer agent = new AgentServer();
        String authSocket;
        try {
            authSocket = agent.start();
        } catch (UnsatisfiedLinkError e) {
            // the native library is not available, so these tests should be skipped
            authSocket = null;
        }
        assumeThat(authSocket, notNullValue());

        SshAgent client = new AgentClient(authSocket);
        List<SshAgent.Pair<PublicKey, String>> keys = client.getIdentities();
        assertNotNull(keys);
        assertEquals(0, keys.size());

        KeyPair[] k = new FileKeyPairProvider(new String[] { "src/test/resources/hostkey.pem"}).loadKeys();
        client.addIdentity(k[0], "");
        keys = client.getIdentities();
        assertNotNull(keys);
        assertEquals(1, keys.size());

        client.removeIdentity(k[0].getPublic());
        keys = client.getIdentities();
        assertNotNull(keys);
        assertEquals(0, keys.size());

        client.removeAllIdentities();

        client.close();

        agent.close();
    }
}
