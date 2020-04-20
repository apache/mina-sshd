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
package org.apache.sshd.client.future;

import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.VerifiableFuture;

/**
 * An {@link SshFuture} for asynchronous channel opening requests.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface OpenFuture extends SshFuture<OpenFuture>, VerifiableFuture<OpenFuture> {
    /**
     * Returns the cause of the connection failure.
     *
     * @return {@code null} if the connect operation is not finished yet, or if the connection attempt is successful
     *         (use {@link #isDone()} to distinguish between the two).
     */
    Throwable getException();

    /**
     * @return <code>true</code> if the connect operation is finished successfully.
     */
    boolean isOpened();

    /**
     * @return {@code true} if the connect operation has been canceled by {@link #cancel()} method.
     */
    boolean isCanceled();

    /**
     * Sets the newly connected session and notifies all threads waiting for this future. This method is invoked by SSHD
     * internally. Please do not call this method directly.
     */
    void setOpened();

    /**
     * Sets the exception caught due to connection failure and notifies all threads waiting for this future. This method
     * is invoked by SSHD internally. Please do not call this method directly.
     *
     * @param exception The caught {@link Throwable}
     */
    void setException(Throwable exception);

    /**
     * Cancels the connection attempt and notifies all threads waiting for this future.
     */
    void cancel();
}
