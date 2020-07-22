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

package org.apache.sshd.sftp.client;

import java.io.IOException;
import java.time.Duration;

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface RawSftpClient {
    /**
     * @param  cmd         Command to send - <B>Note:</B> only lower 8-bits are used
     * @param  buffer      The {@link Buffer} containing the command data
     * @return             The assigned request id
     * @throws IOException if failed to send command
     */
    int send(int cmd, Buffer buffer) throws IOException;

    /**
     * @param  id          The expected request id
     * @return             The received response {@link Buffer} containing the request id
     * @throws IOException If connection closed or interrupted
     */
    Buffer receive(int id) throws IOException;

    /**
     * @param  id          The expected request id
     * @param  timeout     The amount of time to wait for the response
     * @return             The received response {@link Buffer} containing the request id
     * @throws IOException If connection closed or interrupted
     */
    Buffer receive(int id, long timeout) throws IOException;

    /**
     * @param  id          The expected request id
     * @param  timeout     The amount of time to wait for the response
     * @return             The received response {@link Buffer} containing the request id
     * @throws IOException If connection closed or interrupted
     */
    Buffer receive(int id, Duration timeout) throws IOException;
}
