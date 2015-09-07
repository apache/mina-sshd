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

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;

/**
 * Utility class to help with {@link Closeable}s.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class CloseableUtils {

    /**
     * Private Constructor
     */
    private CloseableUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    // TODO once JDK 8+ becomes the minimum for this project, make it a static method in the Closeable interface
    public static void close(Closeable closeable) throws IOException {
        if (closeable == null) {
            return;
        }

        if ((!closeable.isClosed()) && (!closeable.isClosing())) {
            CloseFuture future = closeable.close(true);
            future.await();  // TODO use verify + configurable timeout
        }
    }

    public static CloseFuture closed() {
        CloseFuture future = new DefaultCloseFuture(null);
        future.setClosed();
        return future;
    }
}
