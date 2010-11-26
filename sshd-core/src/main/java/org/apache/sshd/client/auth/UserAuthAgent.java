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
package org.apache.sshd.client.auth;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.AgentClient;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;

/**
 * Authentication delegating to an SSH agent
 */
public class UserAuthAgent implements UserAuth {

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final ClientSessionImpl session;
    private final String username;
    private final SshAgent agent;
    private Iterator<SshAgent.Pair<PublicKey, String>> keys;

    public UserAuthAgent(ClientSessionImpl session, String username) throws IOException {
        this.session = session;
        this.username = username;
        String authSocket = session.getFactoryManager().getProperties().get(SshAgent.SSH_AUTHSOCKET_ENV_NAME);
        SshAgent agent = new AgentClient(authSocket);
        this.agent = agent;
        keys = agent.getIdentities().iterator();
        sendNextKey();
    }

    public String getUsername() {
        return username;
    }

    protected void sendNextKey() throws IOException {
        sendNextKey(keys.next().getFirst());
    }

    protected void sendNextKey(PublicKey key) throws IOException {
        try {
            log.info("Send SSH_MSG_USERAUTH_REQUEST for publickey");
            Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_USERAUTH_REQUEST, 0);
            int pos1 = buffer.wpos() - 1;
            buffer.putString(username);
            buffer.putString("ssh-connection");
            buffer.putString("publickey");
            buffer.putByte((byte) 1);
            buffer.putString((key instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
            int pos2 = buffer.wpos();
            buffer.putPublicKey(key);


            Buffer bs = new Buffer();
            bs.putString(session.getKex().getH());
            bs.putCommand(SshConstants.Message.SSH_MSG_USERAUTH_REQUEST);
            bs.putString(username);
            bs.putString("ssh-connection");
            bs.putString("publickey");
            bs.putByte((byte) 1);
            bs.putString((key instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
            bs.putPublicKey(key);

            Buffer bs2 = new Buffer();
            bs2.putString((key instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
            bs2.putBytes(agent.sign(key, bs.getCompactData()));
            buffer.putBytes(bs2.array(), bs2.rpos(), bs2.available());

            session.writePacket(buffer);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw (IOException) new IOException("Error performing public key authentication").initCause(e);
        }
    }

    public Result next(Buffer buffer) throws IOException {
        SshConstants.Message cmd = buffer.getCommand();
        log.info("Received {}", cmd);
        if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_SUCCESS) {
            return Result.Success;
        } if (cmd == SshConstants.Message.SSH_MSG_USERAUTH_FAILURE) {
            if (keys.hasNext()) {
                sendNextKey(keys.next().getFirst());
                return Result.Continued;
            }
            return Result.Failure;
        } else {
            // TODO: check packets
            return Result.Continued;
        }
    }
}
