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
package org.apache.sshd.common.channel.throttle;

import java.io.IOException;
import java.nio.channels.Channel;

import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * The ChannelStreamWriter is used when writing to the channel data stream. This data is encoded and sent with the
 * {@link org.apache.sshd.common.SshConstants#SSH_MSG_CHANNEL_DATA} and
 * {@link org.apache.sshd.common.SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} commands.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ChannelStreamWriter extends Channel {

    /**
     * Encode and send the given data packet buffer. <B>Note:</B> the buffer has to have 5 bytes free at the beginning
     * to allow the encoding to take place. Also, the write position of the buffer has to be set to the position of the
     * last byte to write.
     *
     * @param  buffer      the buffer to encode and send. <B>NOTE:</B> the buffer must not be touched until the returned
     *                     write future is completed.
     * @return             An {@code IoWriteFuture} that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when encoding or sending the packet
     */
    IoWriteFuture writeData(Buffer buffer) throws IOException;

}
