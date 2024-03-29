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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.PtyChannelConfigurationHolder;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Client channel to run a remote command
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelExec extends PtyCapableChannelSession {

    private final String command;

    private final byte[] cmdBytes;

    public ChannelExec(String command, PtyChannelConfigurationHolder configHolder, Map<String, ?> env) {
        this(command, StandardCharsets.UTF_8, configHolder, env);
    }

    public ChannelExec(String command, Charset charset, PtyChannelConfigurationHolder configHolder, Map<String, ?> env) {
        super(false, configHolder, env);
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "Command may not be null/empty");
        this.cmdBytes = this.command.getBytes(charset);
    }

    public ChannelExec(byte[] command, PtyChannelConfigurationHolder configHolder, Map<String, ?> env) {
        super(false, configHolder, env);
        this.cmdBytes = ValidateUtils.checkNotNullAndNotEmpty(command, "Command may not be null/empty");
        // UTF-8 is likely to be incorrect; if someone uses this constructor, it is likely that the command contains
        // some mixed encoding using different character sets. But the value is used only for logging.
        this.command = new String(command, StandardCharsets.UTF_8);
    }

    @Override
    protected void doOpen() throws IOException {
        doOpenPty();

        if (log.isDebugEnabled()) {
            log.debug("doOpen({}) send SSH_MSG_CHANNEL_REQUEST exec command={}", this, command);
        }

        Session session = getSession();
        boolean wantReply = CoreModuleProperties.REQUEST_EXEC_REPLY.getRequired(this);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, cmdBytes.length + Integer.SIZE);
        buffer.putUInt(getRecipient());
        buffer.putString(Channel.CHANNEL_EXEC);
        buffer.putBoolean(wantReply);
        buffer.putBytes(cmdBytes);
        addPendingRequest(Channel.CHANNEL_EXEC, wantReply);
        writePacket(buffer);

        super.doOpen();
    }

    @Override
    public void handleSuccess() throws IOException {
        Date pending = removePendingRequest(Channel.CHANNEL_EXEC);
        if (log.isDebugEnabled()) {
            log.debug("handleSuccess({}) pending={}, command={}", this, pending, command);
        }
    }

    @Override
    public void handleFailure() throws IOException {
        Date pending = removePendingRequest(Channel.CHANNEL_EXEC);
        if (pending != null) {
            log.warn("handleFailure({}) pending since={}, command={}", this, pending, command);
            close(true);
        }
    }

}
