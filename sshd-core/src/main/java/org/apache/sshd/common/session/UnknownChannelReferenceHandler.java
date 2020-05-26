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

package org.apache.sshd.common.session;

import java.io.IOException;

import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @see    <A HREF="https://tools.ietf.org/html/rfc4254">RFC 4254</A>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface UnknownChannelReferenceHandler {
    /**
     * Invoked when the connection service responsible for handling channel messages receives a message intended for an
     * unknown channel.
     *
     * @param  service     The {@link ConnectionService} instance through which the message was received
     * @param  cmd         The requested command identifier
     * @param  channelId   The (unknown) target channel identifier
     * @param  buffer      The message {@link Buffer} containing the rest of the message
     * @return             The resolved {@link Channel} - if {@code null} then the message for the unknown channel is
     *                     ignored.
     * @throws IOException If failed to handle the request
     */
    Channel handleUnknownChannelCommand(ConnectionService service, byte cmd, int channelId, Buffer buffer) throws IOException;
}
