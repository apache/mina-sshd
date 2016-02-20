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
package org.apache.sshd.common.util.closeable;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.future.CloseFuture;

/**
 * Utility class to help with {@link Closeable}s.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class CloseableUtils {
    /**
     * Timeout (milliseconds) for waiting on a {@link CloseFuture} to successfully
     * complete its action.
     * @see #DEFAULT_CLOSE_WAIT_TIMEOUT
     */
    public static final String CLOSE_WAIT_TIMEOUT = "sshd-close-wait-time";

    /**
     * Default value for {@link #CLOSE_WAIT_TIMEOUT} if none specified
     */
    public static final long DEFAULT_CLOSE_WAIT_TIMEOUT = TimeUnit.SECONDS.toMillis(15L);

    /**
     * Private Constructor
     */
    private CloseableUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    public static long getMaxCloseWaitTime(PropertyResolver resolver) {
        return (resolver == null) ? DEFAULT_CLOSE_WAIT_TIMEOUT : PropertyResolverUtils.getLongProperty(resolver, CLOSE_WAIT_TIMEOUT, DEFAULT_CLOSE_WAIT_TIMEOUT);
    }

    // TODO once JDK 8+ becomes the minimum for this project, make it a static method in the Closeable interface
    public static void close(Closeable closeable) throws IOException {
        if (closeable == null) {
            return;
        }

        if ((!closeable.isClosed()) && (!closeable.isClosing())) {
            CloseFuture future = closeable.close(true);
            long maxWait = (closeable instanceof PropertyResolver) ? getMaxCloseWaitTime((PropertyResolver) closeable) : DEFAULT_CLOSE_WAIT_TIMEOUT;
            boolean successful = future.await(maxWait);
            if (!successful) {
                throw new SocketTimeoutException("Failed to receive closure confirmation within " + maxWait + " millis");
            }
        }
    }
}
