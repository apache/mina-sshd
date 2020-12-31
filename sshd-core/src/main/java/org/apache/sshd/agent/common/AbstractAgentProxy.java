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
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.sshd.agent.SshAgent;
import org.apache.sshd.agent.SshAgentConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractAgentProxy extends AbstractLoggingBean implements SshAgent, ExecutorServiceCarrier {

    private CloseableExecutorService executor;
    private String channelType = CoreModuleProperties.AGENT_FORWARDING_TYPE_OPENSSH;

    protected AbstractAgentProxy(CloseableExecutorService executorService) {
        executor = executorService;
    }

    public String getChannelType() {
        return channelType;
    }

    public void setChannelType(String channelType) {
        this.channelType = channelType;
    }

    @Override
    public CloseableExecutorService getExecutorService() {
        return executor;
    }

    @Override
    public Iterable<? extends Map.Entry<PublicKey, String>> getIdentities() throws IOException {
        int cmd = SshAgentConstants.SSH2_AGENTC_REQUEST_IDENTITIES;
        int okcmd = SshAgentConstants.SSH2_AGENT_IDENTITIES_ANSWER;
        if (CoreModuleProperties.AGENT_FORWARDING_TYPE_IETF.equals(channelType)) {
            cmd = SshAgentConstants.SSH_AGENT_LIST_KEYS;
            okcmd = SshAgentConstants.SSH_AGENT_KEY_LIST;
        }

        Buffer buffer = createBuffer((byte) cmd, 1);
        buffer = request(prepare(buffer));
        int type = buffer.getUByte();
        if (type != okcmd) {
            throw new SshException("Bad agent identities answer: " + SshAgentConstants.getCommandMessageName(type));
        }

        int nbIdentities = buffer.getInt();
        // TODO make the maximum a Property
        if ((nbIdentities < 0) || (nbIdentities > 1024)) {
            throw new SshException("Illogical identities count: " + nbIdentities);
        }

        List<SimpleImmutableEntry<PublicKey, String>> keys = new ArrayList<>(nbIdentities);
        boolean debugEnabled = log.isDebugEnabled();
        for (int i = 0; i < nbIdentities; i++) {
            PublicKey key = buffer.getPublicKey();
            String comment = buffer.getString();
            if (debugEnabled) {
                log.debug("getIdentities() key type={}, comment={}, fingerprint={}",
                        KeyUtils.getKeyType(key), comment, KeyUtils.getFingerPrint(key));
            }
            keys.add(new SimpleImmutableEntry<>(key, comment));
        }

        return keys;
    }

    @Override
    public Map.Entry<String, byte[]> sign(SessionContext session, PublicKey key, String algo, byte[] data) throws IOException {
        int cmd = SshAgentConstants.SSH2_AGENTC_SIGN_REQUEST;
        int okcmd = SshAgentConstants.SSH2_AGENT_SIGN_RESPONSE;
        if (CoreModuleProperties.AGENT_FORWARDING_TYPE_IETF.equals(channelType)) {
            cmd = SshAgentConstants.SSH_AGENT_PRIVATE_KEY_OP;
            okcmd = SshAgentConstants.SSH_AGENT_OPERATION_COMPLETE;
        }

        Buffer buffer = createBuffer((byte) cmd);
        if (CoreModuleProperties.AGENT_FORWARDING_TYPE_IETF.equals(channelType)) {
            buffer.putString("sign");
        }
        buffer.putPublicKey(key);
        buffer.putBytes(data);
        buffer.putInt(0);
        buffer = request(prepare(buffer));

        int responseType = buffer.getUByte();
        if (responseType != okcmd) {
            throw new SshException("Bad signing response type: " + SshAgentConstants.getCommandMessageName(responseType));
        }

        byte[] signature = buffer.getBytes();
        boolean debugEnabled = log.isDebugEnabled();
        String keyType = KeyUtils.getKeyType(key);
        if (CoreModuleProperties.AGENT_FORWARDING_TYPE_IETF.equals(channelType)) {
            if (debugEnabled) {
                log.debug("sign({}/{})[{}] : {}",
                        algo, keyType, KeyUtils.getFingerPrint(key), BufferUtils.toHex(':', signature));
            }
            return new SimpleImmutableEntry<>(keyType, signature);
        } else {
            Buffer buf = new ByteArrayBuffer(signature);
            String algorithm = buf.getString();
            signature = buf.getBytes();
            if (debugEnabled) {
                log.debug("sign({}/{})[{}] {}: {}",
                        algo, keyType, KeyUtils.getFingerPrint(key), algorithm, BufferUtils.toHex(':', signature));
            }
            return new SimpleImmutableEntry<>(algorithm, signature);
        }
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
            throw new SshException(
                    "Bad addIdentity response (" + SshAgentConstants.getCommandMessageName(response) + ") - available="
                                   + available);
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
            throw new SshException(
                    "Bad removeIdentity response (" + SshAgentConstants.getCommandMessageName(response) + ") - available="
                                   + available);
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
            throw new SshException(
                    "Bad removeAllIdentities response (" + SshAgentConstants.getCommandMessageName(response) + ") - available="
                                   + available);
        }
    }

    @Override
    public void close() throws IOException {
        CloseableExecutorService service = getExecutorService();
        if ((service != null) && (!service.isShutdown())) {
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
