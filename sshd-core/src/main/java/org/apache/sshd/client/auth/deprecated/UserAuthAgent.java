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
package org.apache.sshd.client.auth.deprecated;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Iterator;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.client.session.ClientSessionImpl;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.KeyUtils;

/**
 * Authentication delegating to an SSH agent
 */
public class UserAuthAgent extends AbstractUserAuth {

    private final SshAgent agent;
    private final Iterator<SshAgent.Pair<PublicKey, String>> keys;

    public UserAuthAgent(ClientSessionImpl session, String service) throws IOException {
        super(session, service);
        if (session.getFactoryManager().getAgentFactory() == null) {
            throw new IllegalStateException("No ssh agent factory has been configured");
        }
        this.agent = session.getFactoryManager().getAgentFactory().createClient(session.getFactoryManager());
        this.keys = agent.getIdentities().iterator();
    }

    protected void sendNextKey(PublicKey key) throws IOException {
        try {
            log.debug("Send SSH_MSG_USERAUTH_REQUEST for publickey");
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            int pos1 = buffer.wpos() - 1;
            buffer.putString(session.getUsername());
            buffer.putString(service);
            buffer.putString("publickey");
            buffer.putByte((byte) 1);
            buffer.putString(KeyUtils.getKeyType(key));
            int pos2 = buffer.wpos();
            buffer.putPublicKey(key);


            Buffer bs = new Buffer();
            bs.putString(session.getKex().getH());
            bs.putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST);
            bs.putString(session.getUsername());
            bs.putString(service);
            bs.putString("publickey");
            bs.putByte((byte) 1);
            bs.putString(KeyUtils.getKeyType(key));
            bs.putPublicKey(key);

            Buffer bs2 = new Buffer();
            bs2.putString(KeyUtils.getKeyType(key));
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
        if (buffer == null) {
            if (keys.hasNext()) {
                sendNextKey(keys.next().getFirst());
                return Result.Continued;
            } else {
                agent.close();
                return Result.Failure;
            }
        } else {
            byte cmd = buffer.getByte();
            if (cmd == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                log.info("Received SSH_MSG_USERAUTH_SUCCESS");
                agent.close();
                return Result.Success;
            } if (cmd == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                log.info("Received SSH_MSG_USERAUTH_FAILURE");
                if (keys.hasNext()) {
                    sendNextKey(keys.next().getFirst());
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
