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

import java.util.concurrent.CancellationException;

/**
 * Cancellations may not always be effective immediately. While a cancelled {@link Cancellable} future is considered
 * canceled immediately, it may take some time until the underlying asynchronous operation is really canceled. A
 * cancellation through {@link Cancellable#cancel()} returns a {@code CancelFuture} that can be used to wait for the
 * cancellation to have been effected.
 * <p>
 * A {@code CancelFuture} is not cancellable itself.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    Cancellable
 */
public interface CancelFuture extends SshFuture<CancelFuture>, VerifiableFuture<Boolean> {

    /**
     * Obtains an exception describing the stack trace of where the cancellation was initiated.
     *
     * @return a {@link CancellationException}
     */
    CancellationException getBackTrace();

    /**
     * Tells whether the cancellation has been effected. ({@link #isDone()} {@code && !isCanceled()}) means the
     * cancellation was not effected. In that case check the original operation for a success or failure value.
     *
     * @return {@code true} if the cancellation was done; {@code false} otherwise
     */
    boolean isCanceled();

    /**
     * Marks this {@link CancelFuture} as the cancellation having been effected.
     * <p>
     * This is a framework-internal method.
     * </p>
     */
    void setCanceled();

    /**
     * Marks this {@link CancelFuture} as the cancellation having been effected.
     * <p>
     * This is a framework-internal method.
     * </p>
     *
     * @param error optional {@link Throwable}, if non-{@code null}, it'll be attached to the backtrace.
     */
    void setCanceled(Throwable error);

    /**
     * Sets a {@link CancellationException} describing the stack trace of where the cancellation was initiated. Has no
     * effect if a backtrace was already set, or the given backtrace is {@code null}.
     * <p>
     * This is a framework-internal method.
     * </p>
     *
     * @param backTrace {@link CancellationException} to set
     */
    void setBackTrace(CancellationException backTrace);

    /**
     * Completes this future with a value indicating that the cancellation was not done.
     */
    void setNotCanceled();
}
