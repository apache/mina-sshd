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
 * Represents the completion of an asynchronous SSH operation on a given object (it may be an SSH session or an SSH
 * channel). Can be listened for completion using a {@link SshFutureListener}.
 *
 * @param  <T> Type of future
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SshFuture<T extends SshFuture> extends WaitableFuture {
    /**
     * Adds an event <tt>listener</tt> which is notified when this future is completed. If the listener is added after
     * the completion, the listener is directly notified.
     *
     * @param  listener The {@link SshFutureListener} instance to add
     * @return          The future instance
     */
    T addListener(SshFutureListener<T> listener);

    /**
     * Removes an existing event <tt>listener</tt> so it won't be notified when the future is completed.
     *
     * @param  listener The {@link SshFutureListener} instance to remove
     * @return          The future instance
     */
    T removeListener(SshFutureListener<T> listener);
}
