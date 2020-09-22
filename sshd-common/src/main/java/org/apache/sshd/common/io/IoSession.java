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

import java.io.IOException;
import java.net.SocketAddress;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.net.ConnectionEndpointsIndicator;

public interface IoSession extends ConnectionEndpointsIndicator, Closeable {

    /**
     * @return a unique identifier for this session. Every session has its own ID which is different from any other.
     */
    long getId();

    /**
     * @return The service address through which this session was accepted - {@code null} if session was initiated by
     *         this peer instead of being accepted
     */
    SocketAddress getAcceptanceAddress();

    /**
     * Returns the value of the user-defined attribute of this session.
     *
     * @param  key the key of the attribute
     * @return     {@code null} if there is no attribute with the specified key
     */
    Object getAttribute(Object key);

    /**
     * Sets a user-defined attribute.
     *
     * @param  key   the key of the attribute
     * @param  value the value of the attribute
     * @return       The old value of the attribute - {@code null} if it is new.
     */
    Object setAttribute(Object key, Object value);

    /**
     * Sets a user defined attribute if the attribute with the specified key is not set yet. This method is same with
     * the following code except that the operation is performed atomically.
     * 
     * <pre>
     * <code>
     * if (containsAttribute(key)) {
     *     return getAttribute(key);
     * } else {
     *     return setAttribute(key, value);
     * }
     * </code>
     * </pre>
     *
     * @param  key   The key of the attribute we want to set
     * @param  value The value we want to set
     * @return       The old value of the attribute - {@code null} if not found.
     */
    Object setAttributeIfAbsent(Object key, Object value);

    /**
     * Removes a user-defined attribute with the specified key.
     *
     * @param  key The key of the attribute we want to remove
     * @return     The old value of the attribute - {@code null} if not found.
     */
    Object removeAttribute(Object key);

    /**
     * Write a packet on the socket. Multiple writes can be issued concurrently and will be queued.
     *
     * @param  buffer      the buffer send. <B>NOTE:</B> the buffer must not be touched until the returned write future
     *                     is completed.
     * @return             An {@code IoWriteFuture} that can be used to check when the packet has actually been sent
     * @throws IOException if an error occurred when sending the packet
     */
    IoWriteFuture writeBuffer(Buffer buffer) throws IOException;

    /**
     * Closes this session immediately or after all queued write requests are flushed. This operation is asynchronous.
     * Wait for the returned {@link CloseFuture} if you want to wait for the session actually closed.
     *
     * @param  immediately {@code true} to close this session immediately. The pending write requests will simply be
     *                     discarded. {@code false} to close this session after all queued write requests are flushed.
     * @return             The generated {@link CloseFuture}
     */
    @Override
    CloseFuture close(boolean immediately);

    /**
     * @return the {@link IoService} that created this session.
     */
    IoService getService();

    /**
     * Handle received EOF.
     * 
     * @throws IOException If failed to shutdown the stream
     */
    void shutdownOutputStream() throws IOException;

    /**
     * Suspend read operations on this session. May do nothing if not supported by the session implementation.
     *
     * If the session usage includes a graceful shutdown with messages being exchanged, the caller needs to take care of
     * resuming reading the input in order to actually be able to carry on the conversation with the peer.
     */
    default void suspendRead() {
        // Do nothing by default, but can be overriden by implementations
    }

    /**
     * Resume read operations on this session. May do nothing if not supported by the session implementation.
     */
    default void resumeRead() {
        // Do nothing by default, but can be overriden by implementations
    }

}
