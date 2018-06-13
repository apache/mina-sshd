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

package org.apache.sshd.server.subsystem.sftp;

import java.io.Closeable;
import java.nio.file.Path;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

public class TreeLockExecutor implements Closeable {

    private static final Runnable CLOSE = () -> { /* do nothing - just a marker */ };

    private final ExecutorService executor;
    private final BlockingQueue<Runnable> queue = new LinkedBlockingQueue<>();
    private final Future<?> future;
    private final Function<String, Path> resolver;

    public TreeLockExecutor(ExecutorService executor, Function<String, Path> resolver) {
        this.executor = executor;
        this.resolver = resolver;
        this.future = executor.submit(this::run);
    }

    public void submit(Runnable work, String... paths) {
        queue.add(work);
    }

    protected void run() {
        while (true) {
            try {
                Runnable work = queue.take();
                if (work == CLOSE) {
                    break;
                }
                work.run();
            } catch (Throwable t) {
                // ignore
            }
        }
    }

    @Override
    public void close() {
        queue.clear();
        queue.add(CLOSE);
        try {
            future.get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            // Ignore
        }
        future.cancel(true);
    }
}
