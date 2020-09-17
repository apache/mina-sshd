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

import org.apache.sshd.common.channel.Channel;

/**
 * A special mechanism that enables users to intervene in the way packets are sent from {@code ChannelOutputStream}-s -
 * e.g., by introducing throttling
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface ChannelStreamWriterResolver {
    /**
     * An identity resolver - i.e., no special intervention - simply use the channel itself
     */
    ChannelStreamWriterResolver NONE = (channel, cmd) -> new DefaultChannelStreamWriter(channel);

    /**
     * @param  channel The original {@link Channel}
     * @param  cmd     The {@code SSH_MSG_CHANNEL_DATA} or {@code SSH_MSG_CHANNEL_EXTENDED_DATA} command that triggered
     *                 the resolution
     * @return         The {@link ChannelStreamWriter} to use - <B>Note:</B> if the return value is not a
     *                 {@link Channel} then it will be closed when the stream is closed
     */
    ChannelStreamWriter resolveChannelStreamWriter(Channel channel, byte cmd);

}
