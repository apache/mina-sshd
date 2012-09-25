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

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.AbstractChannel;
import org.apache.sshd.common.util.Buffer;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractServerChannel extends AbstractChannel {

    protected boolean exitStatusSent;

    public OpenFuture open(int recipient, int rwsize, int rmpsize, Buffer buffer) {
        this.recipient = recipient;
        this.remoteWindow.init(rwsize, rmpsize);
        configureWindow();
        return doInit(buffer);
    }

    public void handleOpenSuccess(int recipient, int rwsize, int rmpsize, Buffer buffer) throws IOException {
        throw new IllegalStateException();
    }

    public void handleOpenFailure(Buffer buffer) {
        throw new IllegalStateException();
    }

    protected OpenFuture doInit(Buffer buffer) {
        OpenFuture f = new DefaultOpenFuture(this);
        f.setOpened();
        return f;
    }

    protected void sendExitStatus(int v) throws IOException {
        if (!exitStatusSent) {
            exitStatusSent = true;
            log.debug("Send SSH_MSG_CHANNEL_REQUEST exit-status on channel {}", id);
            Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST, 0);
            buffer.putInt(recipient);
            buffer.putString("exit-status");
            buffer.putByte((byte) 0);
            buffer.putInt(v);
            session.writePacket(buffer);
        }
    }

}
