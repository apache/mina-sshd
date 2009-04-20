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
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public class ChannelShell extends ChannelSession {

    protected void doOpenShell() throws Exception {
        super.doOpenShell();

        Buffer buffer;

        log.info("Send SSH_MSG_CHANNEL_REQUEST pty-req");
        buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST);
        buffer.putInt(recipient);
        buffer.putString("pty-req");
        buffer.putBoolean(false);
        buffer.putString(System.getProperty("TERM", "dummy"));
        buffer.putInt(80);
        buffer.putInt(24);
        buffer.putInt(640);
        buffer.putInt(480);
        Buffer modes = new Buffer();
        modes.putByte((byte) 50); // ISIG
        modes.putInt(1);
        modes.putByte((byte) 51); // ICANON
        modes.putInt(1);
        modes.putByte((byte) 53); // ECHO
        modes.putInt(1);
        modes.putByte((byte) 54); // ECHOE
        modes.putInt(1);
        modes.putByte((byte) 55); // ECHOK
        modes.putInt(1);
        modes.putByte((byte) 56); // ECHONL
        modes.putInt(0);
        modes.putByte((byte) 57); // NOFLSH
        modes.putInt(0);
        modes.putByte((byte) 0);
        buffer.putBytes(modes.getCompactData());
        session.writePacket(buffer);

//        log.info("Send SSH_MSG_CHANNEL_REQUEST env");
//        buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST);
//        buffer.putInt(recipient);
//        buffer.putString("env");
//        session.writePacket(buffer);

        log.info("Send SSH_MSG_CHANNEL_REQUEST shell");
        buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_REQUEST);
        buffer.putInt(recipient);
        buffer.putString("shell");
        buffer.putBoolean(false);
        session.writePacket(buffer);

    }
}
