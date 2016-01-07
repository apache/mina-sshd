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

import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Client channel to run a remote command
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelExec extends PtyCapableChannelSession {
    /**
     * Configure whether reply for the &quot;exec&quot; request is required
     * @see #DEFAULT_REQUEST_EXEC_REPLY
     */
    public static final String REQUEST_EXEC_REPLY = "channel-exec-want-reply";
    public static final boolean DEFAULT_REQUEST_EXEC_REPLY = false;

    private final String command;

    public ChannelExec(String command) {
        super(false);
        this.command = ValidateUtils.checkNotNullAndNotEmpty(command, "Command may not be null/empty");
    }

    @Override
    protected void doOpen() throws IOException {
        doOpenPty();

        if (log.isDebugEnabled()) {
            log.debug("doOpen({}) send SSH_MSG_CHANNEL_REQUEST exec command={}", this, command);
        }

        Session session = getSession();
        boolean wantReply = PropertyResolverUtils.getBooleanProperty(this, REQUEST_EXEC_REPLY, DEFAULT_REQUEST_EXEC_REPLY);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, command.length() + Integer.SIZE);
        buffer.putInt(getRecipient());
        buffer.putString(Channel.CHANNEL_EXEC);
        buffer.putBoolean(wantReply);
        buffer.putString(command);
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
