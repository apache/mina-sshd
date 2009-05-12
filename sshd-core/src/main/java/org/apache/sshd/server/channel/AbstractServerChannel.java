/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.channel;

import java.io.IOException;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.ServerChannel;
import org.apache.sshd.server.session.ServerSession;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractServerChannel extends AbstractChannel implements ServerChannel {

    protected boolean exitStatusSent;

    public void init(ServerSession session, int id, int recipient, int rwsize, int rmpsize) {
        this.session = session;
        this.id = id;
        this.recipient = recipient;
        this.remoteWindow.init(rwsize, rmpsize);
        configureWindow();
    }

    protected void sendExitStatus(int v) throws IOException {
        if (!exitStatusSent) {
            exitStatusSent = true;
            log.info("Send SSH_MSG_CHANNEL_REQUEST exit-status on channel {}", id);
            Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST);
            buffer.putInt(recipient);
            buffer.putString("exit-status");
            buffer.putByte((byte) 0);
            buffer.putInt(v);
            session.writePacket(buffer);
        }
    }

}