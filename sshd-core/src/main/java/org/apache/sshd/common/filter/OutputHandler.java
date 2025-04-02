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
package org.apache.sshd.common.filter;

import java.io.IOException;

import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * A general handler for outgoing messages.
 */
public interface OutputHandler {

    /**
     * Sends an outgoing message.
     *
     * @param  cmd       the SSH command code of the buffer being written; must also be included in the buffer
     * @param  message   {@link Buffer} containing the message; not to be re-used before the returned future is
     *                   fulfilled
     * @return           an {@link IoWriteFuture} that will be fulfilled once the message has been sent.
     * @throws Exception if an error occurs in handling the message
     */
    IoWriteFuture send(int cmd, Buffer message) throws IOException;

}
