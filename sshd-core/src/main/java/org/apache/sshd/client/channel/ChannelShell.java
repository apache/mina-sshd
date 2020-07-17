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
import java.util.Map;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.PtyChannelConfigurationHolder;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * Client channel to open a remote shell
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelShell extends PtyCapableChannelSession {

    public ChannelShell(PtyChannelConfigurationHolder configHolder, Map<String, ?> env) {
        super(true, configHolder, env);
    }

    @Override
    protected void doOpen() throws IOException {
        doOpenPty();

        if (log.isDebugEnabled()) {
            log.debug("doOpen({}) send SSH_MSG_CHANNEL_REQUEST shell", this);
        }

        Session session = getSession();
        boolean wantReply = CoreModuleProperties.REQUEST_SHELL_REPLY.getRequired(this);
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, Integer.SIZE);
        buffer.putInt(getRecipient());
        buffer.putString(Channel.CHANNEL_SHELL);
        buffer.putBoolean(wantReply);
        addPendingRequest(Channel.CHANNEL_SHELL, wantReply);
        writePacket(buffer);

        super.doOpen();
    }

    @Override
    public void handleSuccess() throws IOException {
        Date pending = removePendingRequest(Channel.CHANNEL_SHELL);
        if (log.isDebugEnabled()) {
            log.debug("handleSuccess({}) pending={}", this, pending);
        }
    }

    @Override
    public void handleFailure() throws IOException {
        Date pending = removePendingRequest(Channel.CHANNEL_SHELL);
        if (pending != null) {
            log.warn("handleFailure({}) pending={}", this, pending);
            close(true);
        }
    }
}
