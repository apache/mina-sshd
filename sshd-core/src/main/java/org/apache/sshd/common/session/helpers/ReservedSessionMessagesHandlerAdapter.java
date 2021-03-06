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

import java.util.List;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * Delegates the main interface methods to specific ones after having decoded each message buffer
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ReservedSessionMessagesHandlerAdapter
        extends AbstractLoggingBean
        implements ReservedSessionMessagesHandler {
    public static final ReservedSessionMessagesHandlerAdapter DEFAULT = new ReservedSessionMessagesHandlerAdapter();

    public ReservedSessionMessagesHandlerAdapter() {
        super();
    }

    @Override
    public IoWriteFuture sendIdentification(Session session, String version, List<String> extraLines) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("sendIdentification({}) version={} linesCount={}",
                    session, version, GenericUtils.size(extraLines));
        }

        if (log.isTraceEnabled() && GenericUtils.isNotEmpty(extraLines)) {
            for (String line : extraLines) {
                log.trace("sendIdentification({}) {}", session, line);
            }
        }

        return null;
    }

    @Override
    public void handleIgnoreMessage(Session session, Buffer buffer) throws Exception {
        handleIgnoreMessage(session, buffer.getBytes(), buffer);
    }

    public void handleIgnoreMessage(Session session, byte[] data, Buffer buffer) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleIgnoreMessage({}) SSH_MSG_IGNORE", session);
        }

        if (log.isTraceEnabled()) {
            log.trace("handleIgnoreMessage({}) data: {}", session, BufferUtils.toHex(data));
        }
    }

    @Override
    public void handleDebugMessage(Session session, Buffer buffer) throws Exception {
        handleDebugMessage(session, buffer.getBoolean(), buffer.getString(), buffer.getString(), buffer);
    }

    public void handleDebugMessage(
            Session session, boolean display, String msg, String lang, Buffer buffer)
            throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("handleDebugMessage({}) SSH_MSG_DEBUG (display={}) [lang={}] '{}'",
                    session, display, lang, msg);
        }
    }

    @Override
    public boolean handleUnimplementedMessage(Session session, int cmd, Buffer buffer) throws Exception {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            if (cmd == SshConstants.SSH_MSG_UNIMPLEMENTED) {
                long seqNo = buffer.getUInt();
                log.debug("handleUnimplementedMessage({}) SSH_MSG_UNIMPLEMENTED - seqNo={}", session, seqNo);
            } else {
                log.debug("handleUnimplementedMessage({}): {}", session, SshConstants.getCommandMessageName(cmd));
            }
        }

        return false;
    }
}
