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
package org.apache.sshd.common.session.filters;

import java.util.List;

import org.apache.sshd.common.util.buffer.Buffer;

public interface SshIdentHandler {

    /**
     * Tells whether this {@link SshIdentHandler} is for a server.
     *
     * @return {@code true} if this handler is for a server, {@code false} if it's for a client
     */
    boolean isServer();

    /**
     * Attempts to read the peer's SSH protocol version from the given buffer, following RFC 4253, section 4.2.
     * <p>
     * On a client, the protocol version exchange may contain additional lines before the SSH protocol version is
     * received. The method is supposed to read from the buffer until and including the protocol version, including the
     * terminating CRLF.
     * </p>
     * <p>
     * If no protocol version is found, the method shall return an empty list or {@code null}. It will be called again
     * once more data has been received (again with the full buffer, including the data scanned previously) until it
     * returns a non-empty list (i.e., it found a protocol version string).
     * </p>
     *
     * @param  buffer to scan; upon return {@link Buffer#rpos()} positioned after the last byte consumed
     * @return        the full list of all lines scanned, the last one containing the protocol version, or an empty list
     *                or {@code null} if no protocol version was found in the buffer.
     *
     * @see           <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-4.2">RFC 4253, section 4.2</a>
     */
    List<String> readIdentification(Buffer buffer);

    /**
     * Provides this side's own SSH protocol version, following RFC 4253, section 4.2.
     * <p>
     * On a client, the list should contain only a single string in the format defined in RFC 4253. On a server, the
     * list may contain additional preamble lines; the last line should be the protocol version identification.
     * </p>
     *
     * @return the protocol version lines; must not be empty or {@code null}
     */
    List<String> provideIdentification();

}
