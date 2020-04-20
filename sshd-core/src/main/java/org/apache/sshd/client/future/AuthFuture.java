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
 * An {@link SshFuture} for asynchronous authentication requests.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface AuthFuture extends SshFuture<AuthFuture>, VerifiableFuture<AuthFuture> {
    /**
     * Returns the cause of the authentication failure.
     *
     * @return {@code null} if the authentication operation is not finished yet, or if the connection attempt is
     *         successful (use {@link #isDone()} to distinguish between the two).
     */
    Throwable getException();

    /**
     * @return <code>true</code> if the authentication operation is finished successfully. <B>Note:</B> calling this
     *         method while the operation is in progress returns {@code false}. Should check {@link #isDone()} in order
     *         to ensure that the result is valid.
     */
    boolean isSuccess();

    /**
     * @return <code>false</code> if the authentication operation failed. <B>Note:</B> the operation is considered
     *         failed if an exception is received instead of a success/fail response code or the operation is in
     *         progress. Should check {@link #isDone()} in order to ensure that the result is valid.
     */
    boolean isFailure();

    /**
     * @return {@code true} if the connect operation has been canceled by {@link #cancel()} method.
     */
    boolean isCanceled();

    /**
     * Notifies that the session has been authenticated. This method is invoked by SSHD internally. Please do not call
     * this method directly.
     *
     * @param authed Authentication success state
     */
    void setAuthed(boolean authed);

    /**
     * Sets the exception caught due to connection failure and notifies all threads waiting for this future. This method
     * is invoked by SSHD internally. Please do not call this method directly.
     *
     * @param exception The caught {@link Throwable}
     */
    void setException(Throwable exception);

    /**
     * Cancels the authentication attempt and notifies all threads waiting for this future.
     */
    void cancel();
}
