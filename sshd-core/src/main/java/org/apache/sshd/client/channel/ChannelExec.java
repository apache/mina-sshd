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

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelExec extends PtyCapableChannelSession {

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
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_REQUEST, command.length() + Integer.SIZE);
        buffer.putInt(getRecipient());
        buffer.putString("exec");
        buffer.putBoolean(false);
        buffer.putString(command);
        writePacket(buffer);

        super.doOpen();
    }
}
