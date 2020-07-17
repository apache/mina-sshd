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
package org.apache.sshd.common;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.channels.Channel;
import java.time.Duration;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;

/**
 * A {@code Closeable} is a resource that can be closed. The close method is invoked to release resources that the
 * object is holding. The user can pre-register listeners to be notified when resource close is completed (successfully
 * or otherwise)
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Closeable extends Channel {

    /**
     * Close this resource asynchronously and return a future. Resources support two closing modes: a graceful mode
     * which will cleanly close the resource and an immediate mode which will close the resources abruptly.
     *
     * @param  immediately <code>true</code> if the resource should be shut down abruptly, <code>false</code> for a
     *                     graceful close
     * @return             a {@link CloseFuture} representing the close request
     */
    CloseFuture close(boolean immediately);

    /**
     * Pre-register a listener to be informed when resource is closed. If resource is already closed, the listener will
     * be invoked immediately and not registered for future notification
     *
     * @param listener The notification {@link SshFutureListener} - never {@code null}
     */
    void addCloseFutureListener(SshFutureListener<CloseFuture> listener);

    /**
     * Remove a pre-registered close event listener
     *
     * @param listener The register {@link SshFutureListener} - never {@code null}. Ignored if not registered or
     *                 resource already closed
     */
    void removeCloseFutureListener(SshFutureListener<CloseFuture> listener);

    /**
     * Returns <code>true</code> if this object has been closed.
     *
     * @return <code>true</code> if closing
     */
    boolean isClosed();

    /**
     * Returns <code>true</code> if the {@link #close(boolean)} method has been called. Note that this method will
     * return <code>true</code> even if this {@link #isClosed()} returns <code>true</code>.
     *
     * @return <code>true</code> if closing
     */
    boolean isClosing();

    @Override
    default boolean isOpen() {
        return !(isClosed() || isClosing());
    }

    @Override
    default void close() throws IOException {
        Closeable.close(this);
    }

    static Duration getMaxCloseWaitTime(PropertyResolver resolver) {
        return CommonModuleProperties.CLOSE_WAIT_TIMEOUT.getRequired(resolver);
    }

    static void close(Closeable closeable) throws IOException {
        if (closeable == null) {
            return;
        }

        if ((!closeable.isClosed()) && (!closeable.isClosing())) {
            CloseFuture future = closeable.close(true);
            Duration maxWait = (closeable instanceof PropertyResolver)
                    ? getMaxCloseWaitTime((PropertyResolver) closeable)
                    : CommonModuleProperties.CLOSE_WAIT_TIMEOUT.getRequiredDefault();
            boolean successful = future.await(maxWait);
            if (!successful) {
                throw new SocketTimeoutException("Failed to receive closure confirmation within " + maxWait + " millis");
            }
        }
    }
}
