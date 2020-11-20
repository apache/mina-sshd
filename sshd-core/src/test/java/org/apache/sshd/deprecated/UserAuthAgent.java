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

package org.apache.sshd.deprecated;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Map;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.client.ClientFactoryManager;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Authentication delegating to an SSH agent
 */
// CHECKSTYLE:OFF
public class UserAuthAgent extends AbstractUserAuth {

    private final SshAgent agent;
    private final Iterator<? extends Map.Entry<PublicKey, String>> keys;

    public UserAuthAgent(ClientSessionImpl session, String service) throws IOException {
        super(session, service);
        ClientFactoryManager factoryManager = session.getFactoryManager();
        SshAgentFactory agentFactory = factoryManager.getAgentFactory();
        if (agentFactory == null) {
            throw new IllegalStateException("No ssh agent factory has been configured");
        }
        this.agent = agentFactory.createClient(factoryManager);
        this.keys = agent.getIdentities().iterator();
    }

    protected void sendNextKey(PublicKey key) throws IOException {
        ClientSession session = getClientSession();
        String service = getService();
        try {
            log.debug("Send SSH_MSG_USERAUTH_REQUEST for publickey");
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            buffer.putString(session.getUsername());
            buffer.putString(service);
            buffer.putString(UserAuthPublicKeyFactory.NAME);
            buffer.putBoolean(true);
            buffer.putString(KeyUtils.getKeyType(key));
            buffer.putPublicKey(key);

            KeyExchange kexValue = session.getKex();
            byte[] hValue = kexValue.getH();
            Buffer bs = new ByteArrayBuffer();
            bs.putBytes(hValue);
            bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            bs.putString(session.getUsername());
            bs.putString(service);
            bs.putString(UserAuthPublicKeyFactory.NAME);
            bs.putBoolean(true);
            bs.putString(KeyUtils.getKeyType(key));
            bs.putPublicKey(key);

            String keyType = KeyUtils.getKeyType(key);
            byte[] contents = bs.getCompactData();
            Map.Entry<String, byte[]> result = agent.sign(session, key, keyType, contents);
            String algo = result.getKey();
            byte[] signature = result.getValue();
            Buffer bs2 = new ByteArrayBuffer(algo.length() + signature.length + Long.SIZE, false);
            bs2.putString(algo);
            bs2.putBytes(signature);
            buffer.putBytes(bs2.array(), bs2.rpos(), bs2.available());

            session.writePacket(buffer);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Error performing public key authentication", e);
        }
    }

    @Override
    public Result next(Buffer buffer) throws IOException {
        if (buffer == null) {
            if (keys.hasNext()) {
                Map.Entry<PublicKey, String> nextKeyValue = keys.next();
                sendNextKey(nextKeyValue.getKey());
                return Result.Continued;
            } else {
                agent.close();
                return Result.Failure;
            }
        } else {
            int cmd = buffer.getUByte();
            if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                log.info("Received SSH_MSG_USERAUTH_SUCCESS");
                agent.close();
                return Result.Success;
            }
            if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                String methods = buffer.getString();
                boolean partial = buffer.getBoolean();
                if (log.isDebugEnabled()) {
                    log.debug("Received SSH_MSG_USERAUTH_FAILURE - partial={}, methods={}", partial, methods);
                }
                if (keys.hasNext()) {
                    Map.Entry<PublicKey, String> nextKeyValue = keys.next();
                    sendNextKey(nextKeyValue.getKey());
                    return Result.Continued;
                } else {
                    agent.close();
                    return Result.Failure;
                }
            } else {
                // TODO: check packets
                log.info("Received unknown packet: {}", cmd);
                return Result.Continued;
            }
        }
    }
}
// CHECKSTYLE:ON
