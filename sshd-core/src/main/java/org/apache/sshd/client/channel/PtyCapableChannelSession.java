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
package org.apache.sshd.client.channel;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.PtyChannelConfiguration;
import org.apache.sshd.common.channel.PtyChannelConfigurationHolder;
import org.apache.sshd.common.channel.PtyChannelConfigurationMutator;
import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * <P>
 * Serves as the base channel session for executing remote commands - including a full shell. <B>Note:</B> all the
 * configuration changes via the various {@code setXXX} methods must be made <U>before</U> the channel is actually open.
 * If they are invoked afterwards then they have no effect (silently ignored).
 * </P>
 * <P>
 * A typical code snippet would be:
 * </P>
 * 
 * <pre>
 * <code>
 * try (client = SshClient.setUpDefaultClient()) {
 *      client.start();
 *
 *      try (ClientSession s = client.connect(getCurrentTestName(), "localhost", port).verify(CONNECT_TIMEOUT).getSession()) {
 *          s.addPasswordIdentity(getCurrentTestName());
 *          s.auth().verify(AUTH_TIMEOUT);
 *
 *          try (ChannelExec shell = s.createExecChannel("my super duper command")) {
 *              shell.setEnv("var1", "val1");
 *              shell.setEnv("var2", "val2");
 *              ...etc...
 *
 *              shell.setPtyType(...);
 *              shell.setPtyLines(...);
 *              ...etc...
 *
 *              shell.open().verify(OPEN_TIMEOUT);
 *              shell.waitFor(ClientChannel.CLOSED, TimeUnit.SECONDS.toMillis(17L));    // can use zero for infinite wait
 *
 *              Integer status = shell.getExitStatus();
 *              if (status.intValue() != 0) {
 *                  ...error...
 *              }
 *          }
 *      } finally {
 *          client.stop();
 *      }
 * }
 * </code>
 * </pre>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PtyCapableChannelSession extends ChannelSession implements PtyChannelConfigurationMutator {
    private boolean agentForwarding;
    private boolean usePty;
    private final Map<String, Object> env = new LinkedHashMap<>();
    private final PtyChannelConfiguration config;

    public PtyCapableChannelSession(
                                    boolean usePty, PtyChannelConfigurationHolder configHolder, Map<String, ?> env) {
        this.usePty = usePty;
        this.config = PtyChannelConfigurationMutator.copyConfiguration(
                configHolder, new PtyChannelConfiguration());
        this.config.setPtyType(resolvePtyType(this.config));
        if (GenericUtils.isNotEmpty(env)) {
            for (Map.Entry<String, ?> ee : env.entrySet()) {
                setEnv(ee.getKey(), ee.getValue());
            }
        }
    }

    protected String resolvePtyType(PtyChannelConfigurationHolder configHolder) {
        String ptyType = configHolder.getPtyType();
        if (GenericUtils.isNotEmpty(ptyType)) {
            return ptyType;
        }

        ptyType = System.getenv("TERM");
        if (GenericUtils.isNotEmpty(ptyType)) {
            return ptyType;
        }

        return DUMMY_PTY_TYPE;
    }

    public void setupSensibleDefaultPty() {
        try {
            PtyChannelConfigurationMutator.setupSensitiveDefaultPtyConfiguration(this);
        } catch (Throwable t) {
            debug("setupSensibleDefaultPty({}) Failed ({}) to setup: {}",
                    this, t.getClass().getSimpleName(), t.getMessage(), t);
        }
    }

    public boolean isAgentForwarding() {
        return agentForwarding;
    }

    public void setAgentForwarding(boolean agentForwarding) {
        this.agentForwarding = agentForwarding;
    }

    public boolean isUsePty() {
        return usePty;
    }

    public void setUsePty(boolean usePty) {
        this.usePty = usePty;
    }

    @Override
    public String getPtyType() {
        return config.getPtyType();
    }

    @Override
    public void setPtyType(String ptyType) {
        config.setPtyType(ptyType);
    }

    @Override
    public int getPtyColumns() {
        return config.getPtyColumns();
    }

    @Override
    public void setPtyColumns(int ptyColumns) {
        config.setPtyColumns(ptyColumns);
    }

    @Override
    public int getPtyLines() {
        return config.getPtyLines();
    }

    @Override
    public void setPtyLines(int ptyLines) {
        config.setPtyLines(ptyLines);
    }

    @Override
    public int getPtyWidth() {
        return config.getPtyWidth();
    }

    @Override
    public void setPtyWidth(int ptyWidth) {
        config.setPtyWidth(ptyWidth);
    }

    @Override
    public int getPtyHeight() {
        return config.getPtyHeight();
    }

    @Override
    public void setPtyHeight(int ptyHeight) {
        config.setPtyHeight(ptyHeight);
    }

    @Override
    public Map<PtyMode, Integer> getPtyModes() {
        return config.getPtyModes();
    }

    @Override
    public void setPtyModes(Map<PtyMode, Integer> ptyModes) {
        config.setPtyModes((ptyModes == null) ? Collections.emptyMap() : ptyModes);
    }

    /**
     * @param  key   The (never {@code null}) key (Note: may be empty...)
     * @param  value The value to set - if {@code null} then the pre-existing value for the key (if any) is
     *               <U>removed</U>.
     * @return       The replaced/removed previous value - {@code null} if no previous value set for the key.
     */
    public Object setEnv(String key, Object value) {
        ValidateUtils.checkNotNull(key, "No key provided");
        if (value == null) {
            return env.remove(key);
        } else {
            return env.put(key, value);
        }
    }

    public void sendWindowChange(int columns, int lines) throws IOException {
        sendWindowChange(columns, lines, getPtyHeight(), getPtyWidth());
    }

    public void sendWindowChange(int columns, int lines, int height, int width) throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("sendWindowChange({}) cols={}, lines={}, height={}, width={}",
                    this, columns, lines, height, width);
        }

        setPtyColumns(columns);
        setPtyLines(lines);
        setPtyHeight(height);
        setPtyWidth(width);

        Session session = getSession();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, Long.SIZE);
        buffer.putInt(getRecipient());
        buffer.putString("window-change");
        buffer.putBoolean(false); // want-reply
        buffer.putInt(getPtyColumns());
        buffer.putInt(getPtyLines());
        buffer.putInt(getPtyHeight());
        buffer.putInt(getPtyWidth());
        writePacket(buffer);
    }

    protected void doOpenPty() throws IOException {
        Session session = getSession();
        boolean debugEnabled = log.isDebugEnabled();
        if (agentForwarding) {
            if (debugEnabled) {
                log.debug("doOpenPty({}) Send agent forwarding request", this);
            }

            String channelType = CoreModuleProperties.PROXY_AUTH_CHANNEL_TYPE.getRequired(session);
            Buffer buffer = session.createBuffer(
                    SshConstants.SSH_MSG_CHANNEL_REQUEST, Long.SIZE);
            buffer.putInt(getRecipient());
            buffer.putString(channelType);
            buffer.putBoolean(false); // want-reply
            writePacket(buffer);
        }

        if (usePty) {
            if (debugEnabled) {
                log.debug("doOpenPty({}) Send SSH_MSG_CHANNEL_REQUEST pty-req: {}", this, config);
            }

            Buffer buffer = session.createBuffer(
                    SshConstants.SSH_MSG_CHANNEL_REQUEST, Byte.MAX_VALUE);
            buffer.putInt(getRecipient());
            buffer.putString("pty-req");
            buffer.putBoolean(false); // want-reply
            buffer.putString(getPtyType());
            buffer.putInt(getPtyColumns());
            buffer.putInt(getPtyLines());
            buffer.putInt(getPtyHeight());
            buffer.putInt(getPtyWidth());

            Map<PtyMode, Integer> ptyModes = getPtyModes();
            int numModes = GenericUtils.size(ptyModes);
            Buffer modes = new ByteArrayBuffer(numModes * (1 + Integer.BYTES) + Long.SIZE, false);
            if (numModes > 0) {
                ptyModes.forEach((mode, value) -> {
                    modes.putByte((byte) mode.toInt());
                    modes.putInt(value.longValue());
                });
            }
            modes.putByte(PtyMode.TTY_OP_END);
            buffer.putBytes(modes.getCompactData());
            writePacket(buffer);
        }

        if (GenericUtils.size(env) > 0) {
            if (debugEnabled) {
                log.debug("doOpenPty({}) Send SSH_MSG_CHANNEL_REQUEST env: {}", this, env);
            }

            // Cannot use forEach because of the IOException being thrown by writePacket
            for (Map.Entry<String, ?> entry : env.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                String str = Objects.toString(value);
                Buffer buffer = session.createBuffer(
                        SshConstants.SSH_MSG_CHANNEL_REQUEST, key.length() + GenericUtils.length(str) + Integer.SIZE);
                buffer.putInt(getRecipient());
                buffer.putString("env");
                buffer.putBoolean(false); // want-reply
                buffer.putString(key);
                buffer.putString(str);
                writePacket(buffer);
            }
        }
    }
}
