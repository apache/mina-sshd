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
import java.util.Date;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Client channel to run a subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSubsystem extends ChannelSession {

    private final String subsystem;

    /**
     * @param subsystem The subsystem name for the channel - never {@code null} or empty
     */
    public ChannelSubsystem(String subsystem) {
        this.subsystem = ValidateUtils.checkNotNullAndNotEmpty(subsystem, "Subsystem may not be null/empty");
    }

    /**
     * The subsystem name
     *
     * @return The subsystem name for the channel - never {@code null} or empty
     */
    public final String getSubsystem() {
        return subsystem;
    }

    @Override
    protected void doOpen() throws IOException {
        String systemName = getSubsystem();
        if (log.isDebugEnabled()) {
            log.debug("doOpen({}) SSH_MSG_CHANNEL_REQUEST subsystem={}", this, systemName);
        }

        Session session = getSession();
        boolean wantReply = CoreModuleProperties.REQUEST_SUBSYSTEM_REPLY.getRequired(this);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST,
                Channel.CHANNEL_SUBSYSTEM.length() + systemName.length() + Integer.SIZE);
        buffer.putInt(getRecipient());
        buffer.putString(Channel.CHANNEL_SUBSYSTEM);
        buffer.putBoolean(wantReply);
        buffer.putString(systemName);
        addPendingRequest(Channel.CHANNEL_SUBSYSTEM, wantReply);
        writePacket(buffer);

        super.doOpen();
    }

    @Override
    public void handleSuccess() throws IOException {
        String systemName = getSubsystem();
        Date pending = removePendingRequest(Channel.CHANNEL_SUBSYSTEM);
        if (log.isDebugEnabled()) {
            log.debug("handleSuccess({}) subsystem={}, pending since={}", this, systemName, pending);
        }
    }

    @Override
    public void handleFailure() throws IOException {
        String systemName = getSubsystem();
        Date pending = removePendingRequest(Channel.CHANNEL_SUBSYSTEM);
        if (pending != null) {
            log.warn("handleFailure({}) subsystem={}, pending since={}", this, systemName, pending);
            close(true);
        }
    }

    public void onClose(final Runnable run) {
        closeFuture.addListener(future -> run.run());
    }

    @Override
    public String toString() {
        return super.toString() + "[" + getSubsystem() + "]";
    }
}
