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

package org.apache.sshd.server.command;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;

/**
 * Provides a basic useful skeleton for {@link Command} executions
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractCommandSupport
        extends AbstractLoggingBean
        implements Command, Runnable, ExitCallback, ExecutorServiceCarrier {
    private final String command;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private ExitCallback callback;
    private Environment environment;
    private Future<?> cmdFuture;
    private ExecutorService executorService;
    private boolean shutdownOnExit;
    private boolean cbCalled;

    protected AbstractCommandSupport(String command, ExecutorService executorService, boolean shutdownOnExit) {
        this.command = command;

        if (executorService == null) {
            String poolName = GenericUtils.isEmpty(command) ? getClass().getSimpleName() : command.replace(' ', '_').replace('/', ':');
            this.executorService = ThreadUtils.newSingleThreadExecutor(poolName);
            this.shutdownOnExit = true;    // we always close the ad-hoc executor service
        } else {
            this.executorService = executorService;
            this.shutdownOnExit = shutdownOnExit;
        }
    }

    public String getCommand() {
        return command;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executorService;
    }

    @Override
    public boolean isShutdownOnExit() {
        return shutdownOnExit;
    }

    public InputStream getInputStream() {
        return in;
    }

    @Override
    public void setInputStream(InputStream in) {
        this.in = in;
    }

    public OutputStream getOutputStream() {
        return out;
    }

    @Override
    public void setOutputStream(OutputStream out) {
        this.out = out;
    }

    public OutputStream getErrorStream() {
        return err;
    }

    @Override
    public void setErrorStream(OutputStream err) {
        this.err = err;
    }

    public ExitCallback getExitCallback() {
        return callback;
    }

    @Override
    public void setExitCallback(ExitCallback callback) {
        this.callback = callback;
    }

    public Environment getEnvironment() {
        return environment;
    }

    protected Future<?> getStartedCommandFuture() {
        return cmdFuture;
    }

    @Override
    public void start(Environment env) throws IOException {
        environment = env;
        ExecutorService executors = getExecutorService();
        cmdFuture = executors.submit(this);
    }

    @Override
    public void destroy() {
        ExecutorService executors = getExecutorService();
        if ((executors != null) && (!executors.isShutdown()) && isShutdownOnExit()) {
            Collection<Runnable> runners = executors.shutdownNow();
            if (log.isDebugEnabled()) {
                log.debug("destroy() - shutdown executor service - runners count=" + runners.size());
            }
        }
        this.executorService = null;
    }

    @Override
    public void onExit(int exitValue, String exitMessage) {
        if (cbCalled) {
            if (log.isTraceEnabled()) {
                log.trace("onExit({}) ignore exitValue={}, message={} - already called",
                        this, exitValue, exitMessage);
            }
            return;
        }

        ExitCallback cb = getExitCallback();
        try {
            if (log.isDebugEnabled()) {
                log.debug("onExit({}) exiting - value={}, message={}", this, exitValue, exitMessage);
            }
            cb.onExit(exitValue, exitMessage);
        } finally {
            cbCalled = true;
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getCommand() + "]";
    }
}
