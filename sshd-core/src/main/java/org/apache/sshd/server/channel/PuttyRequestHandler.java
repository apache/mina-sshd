/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.channel;

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelRequestHandler;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Handles Putty specific channel requests as indicated by
 * <A HREF="http://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html">Appendix F: SSH-2 names specified for PuTTY</A>
 */
public class PuttyRequestHandler extends AbstractLoggingBean implements ChannelRequestHandler {
    public static final String REQUEST_SUFFIX = "@putty.projects.tartarus.org";

    public PuttyRequestHandler() {
        super();
    }

    @Override
    public Result process(Channel channel, String request, boolean wantReply, Buffer buffer) throws Exception {
        // make sure proper suffix
        if ((GenericUtils.length(request) <= REQUEST_SUFFIX.length())
                || (!request.endsWith(REQUEST_SUFFIX))) {
            return Result.Unsupported;
        }

        String opcode = request.substring(0, request.length() - REQUEST_SUFFIX.length());
        return processPuttyOpcode(channel, request, opcode, wantReply, buffer);
    }

    protected Result processPuttyOpcode(Channel channel, String request, String opcode, boolean wantReply, Buffer buffer) throws Exception {
        if ("simple".equalsIgnoreCase(opcode)) {
            // Quote: "There is no message-specific data"
            return Result.ReplySuccess;
        } else if ("winadj".equalsIgnoreCase(opcode)) {
            // Quote: "Servers MUST treat it as an unrecognized request and respond with SSH_MSG_CHANNEL_FAILURE"
            return Result.ReplyFailure;
        }

        if (log.isDebugEnabled()) {
            log.debug("processPuttyOpcode(" + opcode + ")"
                    + "[buffer size=" + buffer.available() + "]"
                    + "[reply=" + wantReply + "]"
                    + " Unknown request: " + request);
        }

        return Result.ReplyFailure;
    }
}
