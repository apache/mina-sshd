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
package org.apache.sshd.common.future;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Represents the completion of an asynchronous SSH operation on a given object
 * (it may be an SSH session or an SSH channel).
 * Can be listened for completion using a {@link SshFutureListener}.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SshFuture<T extends SshFuture> {

    /**
     * Wait for the asynchronous operation to complete.
     * The attached listeners will be notified when the operation is
     * completed.
     *
     * @return The {@code this} instance
     * @throws IOException if failed - specifically {@link java.io.InterruptedIOException}
     *                     if waiting was interrupted
     */
    T await() throws IOException;

    /**
     * Wait for the asynchronous operation to complete with the specified timeout.
     *
     * @param timeout   The number of time units to wait
     * @param unit      The {@link TimeUnit} for waiting
     * @return {@code true} if the operation is completed.
     * @throws IOException if failed - specifically {@link java.io.InterruptedIOException}
     *                     if waiting was interrupted
     */
    boolean await(long timeout, TimeUnit unit) throws IOException;

    /**
     * Wait for the asynchronous operation to complete with the specified timeout.
     *
     * @param timeoutMillis Wait time in milliseconds
     * @return {@code true} if the operation is completed.
     * @throws IOException if failed - specifically {@link java.io.InterruptedIOException}
     *                     if waiting was interrupted
     */
    boolean await(long timeoutMillis) throws IOException;

    /**
     * Wait for the asynchronous operation to complete uninterruptibly.
     * The attached listeners will be notified when the operation is
     * completed.
     *
     * @return the current future
     */
    T awaitUninterruptibly();

    /**
     * Wait for the asynchronous operation to complete with the specified timeout
     * uninterruptibly.
     *
     * @param timeout   The number of time units to wait
     * @param unit      The {@link TimeUnit} for waiting
     * @return {@code true} if the operation is completed.
     */
    boolean awaitUninterruptibly(long timeout, TimeUnit unit);

    /**
     * Wait for the asynchronous operation to complete with the specified timeout
     * uninterruptibly.
     *
     * @param timeoutMillis Wait time in milliseconds
     * @return {@code true} if the operation is finished.
     */
    boolean awaitUninterruptibly(long timeoutMillis);

    /**
     * @return {@code true} if the asynchronous operation is completed.
     */
    boolean isDone();

    /**
     * Adds an event <tt>listener</tt> which is notified when
     * this future is completed. If the listener is added
     * after the completion, the listener is directly notified.
     *
     * @param listener The {@link SshFutureListener} instance to add
     * @return The future instance
     */
    T addListener(SshFutureListener<T> listener);

    /**
     * Removes an existing event <tt>listener</tt> so it won't be notified when
     * the future is completed.
     *
     * @param listener The {@link SshFutureListener} instance to remove
     * @return The future instance
     */
    T removeListener(SshFutureListener<T> listener);
}
