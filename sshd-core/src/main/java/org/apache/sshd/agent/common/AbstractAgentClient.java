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
package org.apache.sshd.agent.common;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Map;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentConstants;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

public abstract class AbstractAgentClient extends AbstractLoggingBean {

    private final Buffer buffer = new ByteArrayBuffer();
    private final SshAgent agent;

    protected AbstractAgentClient(SshAgent agent) {
        this.agent = agent;
    }

    public synchronized void messageReceived(Buffer message) throws IOException {
        buffer.putBuffer(message);
        int avail = buffer.available();
        if (avail < 4) {
            if (log.isTraceEnabled()) {
                log.trace("Received message total length ({}) below minimum ({})", avail, 4);
            }
            return;
        }

        int rpos = buffer.rpos();
        int len = buffer.getInt();
        // Protect against malicious or corrupted packets
        if (len < 0) {
            throw new StreamCorruptedException("Illogical message length: " + len);
        }
        buffer.rpos(rpos);

        avail = buffer.available();
        if (avail < (len + 4)) {
            if (log.isTraceEnabled()) {
                log.trace("Received request length ({}) below minimum ({})", avail, len + 4);
            }
            return;
        }

        Buffer rep = new ByteArrayBuffer();
        rep.putInt(0);
        rep.rpos(rep.wpos());

        Buffer req = new ByteArrayBuffer(buffer.getBytes());
        int cmd = -1;
        try {
            cmd = req.getUByte();
            process(cmd, req, rep);
        } catch (Exception e) {
            debug("Failed ({}) to handle command={}: {}",
                    e.getClass().getSimpleName(), cmd, e.getMessage(), e);
            rep.clear();
            rep.putInt(0);
            rep.rpos(rep.wpos());
            rep.putInt(1);
            rep.putByte(SshAgentConstants.SSH2_AGENT_FAILURE);
        }
        reply(prepare(rep));
    }

    protected void process(int cmd, Buffer req, Buffer rep) throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("process(cmd={})", SshAgentConstants.getCommandMessageName(cmd));
        }
        switch (cmd) {
            case SshAgentConstants.SSH2_AGENTC_REQUEST_IDENTITIES: {
                Iterable<? extends Map.Entry<PublicKey, String>> ids = agent.getIdentities();
                Collection<? extends Map.Entry<PublicKey, String>> keys;
                if (ids instanceof Collection<?>) {
                    keys = (Collection<? extends Map.Entry<PublicKey, String>>) ids;
                } else {
                    Collection<Map.Entry<PublicKey, String>> c = new LinkedList<>();
                    for (Map.Entry<PublicKey, String> i : ids) {
                        c.add(i);
                    }
                    keys = c;
                }

                rep.putByte(SshAgentConstants.SSH2_AGENT_IDENTITIES_ANSWER);
                rep.putInt(keys.size());
                for (Map.Entry<PublicKey, String> key : keys) {
                    rep.putPublicKey(key.getKey());
                    rep.putString(key.getValue());
                }
                break;
            }
            case SshAgentConstants.SSH2_AGENTC_SIGN_REQUEST: {
                PublicKey signingKey = req.getPublicKey();
                byte[] data = req.getBytes();
                int flags = req.getInt();
                if (debugEnabled) {
                    log.debug("SSH2_AGENTC_SIGN_REQUEST key={}, flags=0x{}, data={}",
                            signingKey.getAlgorithm(), Integer.toHexString(flags), BufferUtils.toHex(':', data));
                }
                String keyType = ValidateUtils.checkNotNullAndNotEmpty(
                        KeyUtils.getKeyType(signingKey),
                        "Cannot resolve key type of %s",
                        signingKey.getClass().getSimpleName());
                Map.Entry<String, byte[]> result = agent.sign(null, signingKey, keyType, data);
                String algo = result.getKey();
                byte[] signature = result.getValue();
                Buffer sig = new ByteArrayBuffer(algo.length() + signature.length + Long.SIZE, false);
                sig.putString(algo);
                sig.putBytes(signature);
                rep.putByte(SshAgentConstants.SSH2_AGENT_SIGN_RESPONSE);
                rep.putBytes(sig.array(), sig.rpos(), sig.available());
                break;
            }
            case SshAgentConstants.SSH2_AGENTC_ADD_IDENTITY: {
                KeyPair keyToAdd = req.getKeyPair();
                String comment = req.getString();
                if (debugEnabled) {
                    log.debug("SSH2_AGENTC_ADD_IDENTITY comment={}", comment);
                }
                agent.addIdentity(keyToAdd, comment);
                rep.putByte(SshAgentConstants.SSH_AGENT_SUCCESS);
                break;
            }
            case SshAgentConstants.SSH2_AGENTC_REMOVE_IDENTITY: {
                PublicKey keyToRemove = req.getPublicKey();
                if (debugEnabled) {
                    log.debug("SSH2_AGENTC_REMOVE_IDENTITY {}", keyToRemove.getClass().getSimpleName());
                }
                agent.removeIdentity(keyToRemove);
                rep.putByte(SshAgentConstants.SSH_AGENT_SUCCESS);
                break;
            }
            case SshAgentConstants.SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
                agent.removeAllIdentities();
                rep.putByte(SshAgentConstants.SSH_AGENT_SUCCESS);
                break;
            default:
                if (debugEnabled) {
                    log.debug("Unknown command: {}", SshAgentConstants.getCommandMessageName(cmd));
                }
                rep.putByte(SshAgentConstants.SSH2_AGENT_FAILURE);
                break;
        }
    }

    protected Buffer prepare(Buffer buf) {
        int len = buf.available();
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
