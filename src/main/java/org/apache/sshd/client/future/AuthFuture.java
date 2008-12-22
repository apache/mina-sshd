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
package org.apache.sshd.client.future;

import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;

/**
 * An {@link SshFuture} for asynchronous authentication requests.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public interface AuthFuture extends SshFuture<AuthFuture> {

    /**
     * Returns the cause of the connection failure.
     *
     * @return <tt>null</tt> if the connect operation is not finished yet,
     *         or if the connection attempt is successful.
     */
    Throwable getException();

    /**
     * Returns <tt>true</tt> if the authentication operation is finished successfully.
     */
    boolean isSuccess();

    /**
     * Returns <tt>false</tt> if the authentication operation failed.
     */
    boolean isFailure();

    /**
     * Returns {@code true} if the connect operation has been canceled by
     * {@link #cancel()} method.
     */
    boolean isCanceled();

    /**
     * Notifies that the session has been authenticated.
     * This method is invoked by SSHD internally.  Please do not
     * call this method directly.
     */
    void setAuthed(boolean authed);

    /**
     * Sets the exception caught due to connection failure and notifies all
     * threads waiting for this future.  This method is invoked by SSHD
     * internally.  Please do not call this method directly.
     */
    void setException(Throwable exception);

    /**
     * Cancels the authentication attempt and notifies all threads waiting for
     * this future.
     */
    void cancel();

}
