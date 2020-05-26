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
package org.apache.sshd.common.io;

import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.VerifiableFuture;

public interface IoWriteFuture extends SshFuture<IoWriteFuture>, VerifiableFuture<IoWriteFuture> {
    /**
     * @return <tt>true</tt> if the write operation is finished successfully.
     */
    boolean isWritten();

    /**
     * @return the cause of the write failure if and only if the write operation has failed due to an {@link Exception}.
     *         Otherwise, {@code null} is returned (use {@link #isDone()} to distinguish between the two.
     */
    Throwable getException();
}
