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
package org.apache.sshd.client.channel;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Buffer;

/**
 * Client channel to run a subsystem
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelSubsystem extends ChannelSession {

    private final String subsystem;

    public ChannelSubsystem(String subsystem) {
        if (subsystem == null) {
            throw new IllegalArgumentException("subsystem must not be null");
        }
        this.subsystem = subsystem;
    }

    protected void doOpen() throws Exception {
        super.doOpen();
        log.info("Send SSH_MSG_CHANNEL_REQUEST exec");
        Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST, 0);
        buffer.putInt(recipient);
        buffer.putString("subsystem");
        buffer.putBoolean(false);
        buffer.putString(subsystem);
        session.writePacket(buffer);

    }
}
