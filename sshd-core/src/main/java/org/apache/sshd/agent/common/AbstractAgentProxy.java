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
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Pair;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractAgentProxy extends AbstractLoggingBean implements SshAgent, ExecutorServiceConfigurer {
    private ExecutorService executor;
    private boolean shutdownExecutor;

    protected AbstractAgentProxy() {
        super();
    }

    @Override
    public ExecutorService getExecutorService() {
        return executor;
    }

    @Override
    public void setExecutorService(ExecutorService service) {
        executor = service;
    }

    @Override
    public boolean isShutdownOnExit() {
        return shutdownExecutor;
    }

    @Override
    public void setShutdownOnExit(boolean shutdown) {
        shutdownExecutor = shutdown;
    }

    @Override
    public List<Pair<PublicKey, String>> getIdentities() throws IOException {
        Buffer buffer = createBuffer(SshAgentConstants.SSH2_AGENTC_REQUEST_IDENTITIES, 1);
        buffer = request(prepare(buffer));
        int type = buffer.getUByte();
        if (type != SshAgentConstants.SSH2_AGENT_IDENTITIES_ANSWER) {
            throw new SshException("Bad agent identities answer: " + SshAgentConstants.getCommandMessageName(type));
        }

        int nbIdentities = buffer.getInt();
        if (nbIdentities > 1024) {
            throw new SshException("Bad identities count: " + nbIdentities);
        }

        List<Pair<PublicKey, String>> keys = new ArrayList<>(nbIdentities);
        for (int i = 0; i < nbIdentities; i++) {
            PublicKey key = buffer.getPublicKey();
            String comment = buffer.getString();
            if (log.isDebugEnabled()) {
                log.debug("getIdentities() key type={}, comment={}, fingerprint={}",
                          KeyUtils.getKeyType(key), comment, KeyUtils.getFingerPrint(key));
            }
            keys.add(new Pair<>(key, comment));
        }

        return keys;
    }

    @Override
    public byte[] sign(PublicKey key, byte[] data) throws IOException {
        Buffer buffer = createBuffer(SshAgentConstants.SSH2_AGENTC_SIGN_REQUEST);
        buffer.putPublicKey(key);
        buffer.putBytes(data);
        buffer.putInt(0);
        buffer = request(prepare(buffer));

        int responseType = buffer.getUByte();
        if (responseType != SshAgentConstants.SSH2_AGENT_SIGN_RESPONSE) {
            throw new SshException("Bad signing response type: " + SshAgentConstants.getCommandMessageName(responseType));
        }

        Buffer buf = new ByteArrayBuffer(buffer.getBytes());
        String algorithm = buf.getString();
        byte[] signature = buf.getBytes();
        if (log.isDebugEnabled()) {
            log.debug("sign({})[{}] {}: {}",
                      KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key),
                      algorithm, BufferUtils.toHex(':', signature));
        }

        return signature;
    }

    @Override
    public void addIdentity(KeyPair kp, String comment) throws IOException {
        Buffer buffer = createBuffer(SshAgentConstants.SSH2_AGENTC_ADD_IDENTITY);
        buffer.putKeyPair(kp);
        buffer.putString(comment);
        if (log.isDebugEnabled()) {
            log.debug("addIdentity({})[{}]: {}", KeyUtils.getKeyType(kp), comment, KeyUtils.getFingerPrint(kp.getPublic()));
        }
        buffer = request(prepare(buffer));

        int available = buffer.available();
        int response = (available >= 1) ? buffer.getUByte() : -1;
        if ((available != 1) || (response != SshAgentConstants.SSH_AGENT_SUCCESS)) {
            throw new SshException("Bad addIdentity response (" + SshAgentConstants.getCommandMessageName(response) + ") - available=" + available);
        }
    }

    @Override
    public void removeIdentity(PublicKey key) throws IOException {
        Buffer buffer = createBuffer(SshAgentConstants.SSH2_AGENTC_REMOVE_IDENTITY);
        buffer.putPublicKey(key);
        if (log.isDebugEnabled()) {
            log.debug("removeIdentity({}) {}", KeyUtils.getKeyType(key), KeyUtils.getFingerPrint(key));
        }

        buffer = request(prepare(buffer));

        int available = buffer.available();
        int response = (available >= 1) ? buffer.getUByte() : -1;
        if ((available != 1) || (response != SshAgentConstants.SSH_AGENT_SUCCESS)) {
            throw new SshException("Bad removeIdentity response (" + SshAgentConstants.getCommandMessageName(response) + ") - available=" + available);
        }
    }

    @Override
    public void removeAllIdentities() throws IOException {
        Buffer buffer = createBuffer(SshAgentConstants.SSH2_AGENTC_REMOVE_ALL_IDENTITIES, 1);
        if (log.isDebugEnabled()) {
            log.debug("removeAllIdentities");
        }
        buffer = request(prepare(buffer));

        int available = buffer.available();
        int response = (available >= 1) ? buffer.getUByte() : -1;
        if ((available != 1) || (response != SshAgentConstants.SSH_AGENT_SUCCESS)) {
            throw new SshException("Bad removeAllIdentities response (" + SshAgentConstants.getCommandMessageName(response) + ") - available=" + available);
        }
    }

    @Override
    public void close() throws IOException {
        ExecutorService service = getExecutorService();
        if ((service != null) && isShutdownOnExit() && (!service.isShutdown())) {
            Collection<?> runners = service.shutdownNow();
            if (log.isDebugEnabled()) {
                log.debug("close() - shutdown runners count=" + GenericUtils.size(runners));
            }
        }
    }

    protected Buffer createBuffer(byte cmd) {
        return createBuffer(cmd, 0);
    }

    protected Buffer createBuffer(byte cmd, int extraLen) {
        Buffer buffer = new ByteArrayBuffer((extraLen <= 0) ? ByteArrayBuffer.DEFAULT_SIZE : extraLen + Byte.SIZE, false);
        buffer.putInt(0);
        buffer.putByte(cmd);
        return buffer;
    }

    protected Buffer prepare(Buffer buffer) {
        int wpos = buffer.wpos();
        buffer.wpos(0);
        buffer.putInt(wpos - 4);
        buffer.wpos(wpos);
        return buffer;
    }

    protected abstract Buffer request(Buffer buffer) throws IOException;

}
