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

/**
 * Some operation that can be cancelled.
 * <p>
 * Classes implementing this interface that support state listeners are expected to notify the listeners when
 * {@link #cancel()} changes the state of the operation.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Cancellable extends WithException {

    /**
     * Attempts to cancel the operation.
     *
     * @return A {@link CancelFuture} that can be used to wait for the cancellation to have been effected, or
     *         {@code null} if the future cannot be canceled or is already completed.
     */
    CancelFuture cancel();

    /**
     * Tells whether this operation was canceled.
     *
     * @return {@code true} if the operation was cancelled, {@code false} otherwise.
     */
    boolean isCanceled();

    /**
     * Retrieves the {@link CancelFuture}, if {@link #cancel()} had been called.
     *
     * @return The {@link CancelFuture} if the {@link Cancellable} has already been canceled, or {@code null} otherwise
     */
    CancelFuture getCancellation();
}
