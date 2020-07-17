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

package org.apache.sshd.common.session.helpers;

import java.io.IOException;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.UnknownChannelReferenceHandler;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultUnknownChannelReferenceHandler
        extends AbstractLoggingBean
        implements UnknownChannelReferenceHandler {

    public static final DefaultUnknownChannelReferenceHandler INSTANCE = new DefaultUnknownChannelReferenceHandler();

    public DefaultUnknownChannelReferenceHandler() {
        super();
    }

    @Override
    public Channel handleUnknownChannelCommand(
            ConnectionService service, byte cmd, int channelId, Buffer buffer)
            throws IOException {
        Session session = service.getSession();
        // Use DEBUG level to avoid log overflow due to invalid messages flood
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("handleUnknownChannelCommand({}) received {} command for unknown channel: {}",
                    session, SshConstants.getCommandMessageName(cmd), channelId);
        }

        boolean wantReply = false;
        switch (cmd) {
            case SshConstants.SSH_MSG_CHANNEL_REQUEST: {
                /*
                 * From RFC 4252 - section 5.4:
                 *
                 * If the request is not recognized or is not supported for the channel, SSH_MSG_CHANNEL_FAILURE is
                 * returned
                 */
                String req = buffer.getString();
                wantReply = buffer.getBoolean();
                // Use DEBUG level to avoid log overflow due to invalid messages flood
                if (debugEnabled) {
                    log.debug(
                            "handleUnknownChannelCommand({}) Received SSH_MSG_CHANNEL_REQUEST={} (wantReply={}) for unknown channel: {}",
                            session, req, wantReply, channelId);
                }
                break;
            }

            case SshConstants.SSH_MSG_CHANNEL_DATA:
            case SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA:
                wantReply = CoreModuleProperties.SEND_REPLY_FOR_CHANNEL_DATA.getRequired(session);
                // Use TRACE level to avoid log overflow due to invalid messages flood
                if (log.isTraceEnabled()) {
                    log.trace("handleUnknownChannelCommand({}) received msg channel data (opcode={}) reply={}",
                            session, cmd, wantReply);
                }
                break;

            default: // do nothing
        }

        if (wantReply) {
            sendFailureResponse(service, cmd, channelId);
        }

        return null;
    }

    protected IoWriteFuture sendFailureResponse(
            ConnectionService service, byte cmd, int channelId)
            throws IOException {
        Session session = service.getSession();
        // Use DEBUG level to avoid log overflow due to invalid messages flood
        if (log.isDebugEnabled()) {
            log.debug("sendFailureResponse({}) send SSH_MSG_CHANNEL_FAILURE for {} command on unknown channel: {}",
                    session, SshConstants.getCommandMessageName(cmd), channelId);
        }

        Buffer rsp = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_FAILURE, Integer.BYTES);
        rsp.putInt(channelId);
        return session.writePacket(rsp);
    }
}
