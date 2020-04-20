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
package org.apache.sshd.common.util.threads;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Wraps an {@link ExecutorService} as a {@link CloseableExecutorService} and avoids calling its {@code shutdown}
 * methods when the wrapper is shut down
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NoCloseExecutor implements CloseableExecutorService {
    protected final ExecutorService executor;
    protected final CloseFuture closeFuture;

    public NoCloseExecutor(ExecutorService executor) {
        this.executor = executor;
        closeFuture = new DefaultCloseFuture(null, null);
    }

    @Override
    public <T> Future<T> submit(Callable<T> task) {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        return executor.submit(task);
    }

    @Override
    public <T> Future<T> submit(Runnable task, T result) {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        return executor.submit(task, result);
    }

    @Override
    public Future<?> submit(Runnable task) {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        return executor.submit(task);
    }

    @Override
    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks)
            throws InterruptedException {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        return executor.invokeAll(tasks);
    }

    @Override
    public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
            throws InterruptedException {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        return executor.invokeAll(tasks, timeout, unit);
    }

    @Override
    public <T> T invokeAny(Collection<? extends Callable<T>> tasks)
            throws InterruptedException, ExecutionException {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        return executor.invokeAny(tasks);
    }

    @Override
    public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
            throws InterruptedException, ExecutionException, TimeoutException {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        return executor.invokeAny(tasks, timeout, unit);
    }

    @Override
    public void execute(Runnable command) {
        ValidateUtils.checkState(!isShutdown(), "Executor has been shut down");
        executor.execute(command);
    }

    @Override
    public void shutdown() {
        close(true);
    }

    @Override
    public List<Runnable> shutdownNow() {
        close(true);
        return Collections.emptyList();
    }

    @Override
    public boolean isShutdown() {
        return isClosed();
    }

    @Override
    public boolean isTerminated() {
        return isClosed();
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        try {
            return closeFuture.await(timeout, unit);
        } catch (IOException e) {
            throw (InterruptedException) new InterruptedException().initCause(e);
        }
    }

    @Override
    public CloseFuture close(boolean immediately) {
        closeFuture.setClosed();
        return closeFuture;
    }

    @Override
    public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
        closeFuture.addListener(listener);
    }

    @Override
    public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
        closeFuture.removeListener(listener);
    }

    @Override
    public boolean isClosed() {
        return closeFuture.isClosed();
    }

    @Override
    public boolean isClosing() {
        return isClosed();
    }

}
