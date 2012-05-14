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
package org.apache.sshd.agent.common;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.util.Buffer;

import static org.apache.sshd.agent.SshAgentConstants.*;

public abstract class AbstractAgentClient {

    private final Buffer buffer = new Buffer();
    private final SshAgent agent;

    public AbstractAgentClient(SshAgent agent) {
        this.agent = agent;
    }

    public synchronized void messageReceived(Buffer message) throws IOException {
        buffer.putBuffer(message);
        if (buffer.available() < 4) {
            return;
        }
        int rpos = buffer.rpos();
        int len = buffer.getInt();
        buffer.rpos(rpos);
        if (buffer.available() < len + 4) {
            return;
        }
        Buffer rep = new Buffer();
        rep.putInt(0);
        rep.rpos(rep.wpos());
        try {
            process(new Buffer(buffer.getBytes()), rep);
        } catch (Exception e) {
            rep.clear();
            rep.putInt(0);
            rep.rpos(rep.wpos());
            rep.putInt(1);
            rep.putByte(SSH2_AGENT_FAILURE);
        }
        reply(prepare(rep));
    }

    protected void process(Buffer req, Buffer rep) throws Exception {
        int cmd = req.getByte();
        switch (cmd) {
            case SSH2_AGENTC_REQUEST_IDENTITIES:
            {
                List<SshAgent.Pair<PublicKey,String>> keys = agent.getIdentities();
                rep.putByte(SSH2_AGENT_IDENTITIES_ANSWER);
                rep.putInt(keys.size());
                for (SshAgent.Pair<PublicKey,String> key : keys) {
                    rep.putPublicKey(key.getFirst());
                    rep.putString(key.getSecond());
                }
                break;
            }
            case SSH2_AGENTC_SIGN_REQUEST:
            {
                PublicKey key = req.getPublicKey();
                byte[] data = req.getBytes();
                int flags = req.getInt();
                Buffer sig = new Buffer();
                sig.putString(key instanceof RSAPublicKey ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS);
                sig.putBytes(agent.sign(key, data));
                rep.putByte(SSH2_AGENT_SIGN_RESPONSE);
                rep.putBytes(sig.array(), sig.rpos(), sig.available());
                break;
            }
            case SSH2_AGENTC_ADD_IDENTITY:
            {
                agent.addIdentity(req.getKeyPair(), req.getString());
                rep.putByte(SSH_AGENT_SUCCESS);
                break;
            }
            case SSH2_AGENTC_REMOVE_IDENTITY:
            {
                PublicKey key = req.getPublicKey();
                agent.removeIdentity(key);
                rep.putByte(SSH_AGENT_SUCCESS);
                break;
            }
            case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
            {
                agent.removeAllIdentities();
                rep.putByte(SSH_AGENT_SUCCESS);
                break;
            }
            default:
            {
                rep.putByte(SSH2_AGENT_FAILURE);
                break;
            }
        }
    }

    protected Buffer prepare(Buffer buf) {
        int len  = buf.available();
        int rpos = buf.rpos();
        int wpos = buf.wpos();
        buf.rpos(rpos - 4);
        buf.wpos(rpos - 4);
        buf.putInt(len);
        buf.wpos(wpos);
        return buf;
    }

    protected abstract void reply(Buffer buf) throws IOException;

}
