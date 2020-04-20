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

package org.apache.sshd.common.future;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Represents an asynchronous operation which one can wait for its completion. <B>Note:</B> the only thing guaranteed is
 * that if {@code true} is returned from one of the {@code awaitXXX} methods then the operation has completed. However,
 * the <B>caller</B> has to determine whether it was a successful or failed completion.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface WaitableFuture {
    /**
     * @return Some identifier useful as {@code toString()} value
     */
    Object getId();

    /**
     * Wait {@link Long#MAX_VALUE} msec. for the asynchronous operation to complete. The attached listeners will be
     * notified when the operation is completed.
     *
     * @return             {@code true} if the operation is completed.
     * @throws IOException if failed - specifically {@link java.io.InterruptedIOException} if waiting was interrupted
     * @see                #await(long)
     */
    default boolean await() throws IOException {
        return await(Long.MAX_VALUE);
    }

    /**
     * Wait for the asynchronous operation to complete with the specified timeout.
     *
     * @param  timeout     The number of time units to wait
     * @param  unit        The {@link TimeUnit} for waiting
     * @return             {@code true} if the operation is completed.
     * @throws IOException if failed - specifically {@link java.io.InterruptedIOException} if waiting was interrupted
     * @see                #await(long)
     */
    default boolean await(long timeout, TimeUnit unit) throws IOException {
        return await(unit.toMillis(timeout));
    }

    /**
     * Wait for the asynchronous operation to complete with the specified timeout.
     *
     * @param  timeout     The maximum duration to wait, <code>null</code> to wait forever
     * @return             {@code true} if the operation is completed.
     * @throws IOException if failed - specifically {@link java.io.InterruptedIOException} if waiting was interrupted
     * @see                #await(long)
     */
    default boolean await(Duration timeout) throws IOException {
        return timeout != null ? await(timeout.toMillis()) : await();
    }

    /**
     * Wait for the asynchronous operation to complete with the specified timeout.
     *
     * @param  timeoutMillis Wait time in milliseconds
     * @return               {@code true} if the operation is completed.
     * @throws IOException   if failed - specifically {@link java.io.InterruptedIOException} if waiting was interrupted
     */
    boolean await(long timeoutMillis) throws IOException;

    /**
     * Wait {@link Long#MAX_VALUE} msec. for the asynchronous operation to complete uninterruptibly. The attached
     * listeners will be notified when the operation is completed.
     *
     * @return {@code true} if the operation is completed.
     * @see    #awaitUninterruptibly(long)
     */
    default boolean awaitUninterruptibly() {
        return awaitUninterruptibly(Long.MAX_VALUE);
    }

    /**
     * Wait for the asynchronous operation to complete with the specified timeout uninterruptibly.
     *
     * @param  timeout The number of time units to wait
     * @param  unit    The {@link TimeUnit} for waiting
     * @return         {@code true} if the operation is completed.
     * @see            #awaitUninterruptibly(long)
     */
    default boolean awaitUninterruptibly(long timeout, TimeUnit unit) {
        return awaitUninterruptibly(unit.toMillis(timeout));
    }

    /**
     * Wait for the asynchronous operation to complete with the specified timeout uninterruptibly.
     *
     * @param  timeoutMillis Wait time, <code>null</code> to wait forever
     * @return               {@code true} if the operation is finished.
     */
    default boolean awaitUninterruptibly(Duration timeoutMillis) {
        return timeoutMillis != null ? awaitUninterruptibly(timeoutMillis.toMillis()) : awaitUninterruptibly();
    }

    /**
     * Wait for the asynchronous operation to complete with the specified timeout uninterruptibly.
     *
     * @param  timeoutMillis Wait time in milliseconds
     * @return               {@code true} if the operation is finished.
     */
    boolean awaitUninterruptibly(long timeoutMillis);

    /**
     * @return {@code true} if the asynchronous operation is completed. <B>Note:</B> it is up to the <B>caller</B> to
     *         determine whether it was a successful or failed completion.
     */
    boolean isDone();
}
