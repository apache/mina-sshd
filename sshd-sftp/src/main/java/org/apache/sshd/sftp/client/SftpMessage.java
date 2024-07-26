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
import java.util.Objects;

import org.apache.sshd.common.io.IoWriteFuture;

/**
 * A representation of a written SFTP message.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpMessage {

    private final int id;
    private final IoWriteFuture future;
    private final Duration timeout;

    /**
     * Creates a new instance.
     *
     * @param id      SFTP message id
     * @param future  {@link IoWriteFuture} of the SFTP message; can be used to wait until the message has been actually
     *                sent
     * @param timeout the configured SFTP write timeout
     */
    public SftpMessage(int id, IoWriteFuture future, Duration timeout) {
        this.id = id;
        this.future = Objects.requireNonNull(future);
        this.timeout = Objects.requireNonNull(timeout);
    }

    /**
     * Retrieves the SFTP message id.
     *
     * @return the SFTP message id
     */
    public int getId() {
        return id;
    }

    /**
     * Retrieves the {@link IoWriteFuture} of the message; can be used to wait until the message has been actually sent.
     *
     * @return the {@link IoWriteFuture}, never {@code null}
     */
    public IoWriteFuture getFuture() {
        return future;
    }

    /**
     * Retrieves the write timeout configured when the message was sent.
     *
     * @return the timeout, never {@code null}
     */
    public Duration getTimeout() {
        return timeout;
    }

    /**
     * Waits with the configured timeout until the message has been sent.
     *
     * @throws IOException if the message could not be sent, or waiting is interrupted.
     */
    public void waitUntilSent() throws IOException {
        getFuture().verify(getTimeout());
    }
}
