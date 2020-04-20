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
import java.util.concurrent.Future;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionHolder;

/**
 * Provides a basic useful skeleton for {@link Command} executions
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractCommandSupport
        extends AbstractLoggingBean
        implements Command, Runnable, ExecutorServiceCarrier, SessionAware,
        SessionHolder<ServerSession>, ServerSessionHolder {
    protected volatile Thread cmdRunner;
    protected CloseableExecutorService executorService;
    protected boolean cbCalled;

    private final String command;
    private InputStream in;
    private OutputStream out;
    private OutputStream err;
    private ExitCallback callback;
    private Environment environment;
    private Future<?> cmdFuture;
    private ServerSession serverSession;

    protected AbstractCommandSupport(String command, CloseableExecutorService executorService) {
        this.command = command;

        if (executorService == null) {
            String poolName = GenericUtils.isEmpty(command)
                    ? getClass().getSimpleName()
                    : command.replace(' ', '_').replace('/', ':');
            this.executorService = ThreadUtils.newSingleThreadExecutor(poolName);
        } else {
            this.executorService = executorService;
        }
    }

    public String getCommand() {
        return command;
    }

    @Override
    public ServerSession getSession() {
        return getServerSession();
    }

    @Override
    public ServerSession getServerSession() {
        return serverSession;
    }

    @Override
    public void setSession(ServerSession session) {
        serverSession = session;
    }

    @Override
    public CloseableExecutorService getExecutorService() {
        return executorService;
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
    public void start(ChannelSession channel, Environment env) throws IOException {
        environment = env;

        String cmd = getCommand();
        try {
            if (log.isDebugEnabled()) {
                log.debug("start({}) starting runner for command={}", channel, cmd);
            }

            CloseableExecutorService executors = getExecutorService();
            cmdFuture = executors.submit(() -> {
                cmdRunner = Thread.currentThread();
                this.run();
            });
        } catch (RuntimeException e) { // e.g., RejectedExecutionException
            log.error("start(" + channel + ")"
                      + " Failed (" + e.getClass().getSimpleName() + ")"
                      + " to start command=" + cmd + ": " + e.getMessage(),
                    e);
            throw new IOException(e);
        }
    }

    @Override
    public void destroy(ChannelSession channel) throws Exception {
        // if thread has not completed, cancel it
        boolean debugEnabled = log.isDebugEnabled();
        if ((cmdFuture != null)
                && (!cmdFuture.isDone())
                && (cmdRunner != Thread.currentThread())) {
            boolean result = cmdFuture.cancel(true);
            // TODO consider waiting some reasonable (?) amount of time for cancellation
            if (debugEnabled) {
                log.debug("destroy({})[{}] - cancel pending future={}", channel, this, result);
            }
        }

        cmdFuture = null;

        CloseableExecutorService executors = getExecutorService();
        if ((executors != null) && (!executors.isShutdown())) {
            Collection<Runnable> runners = executors.shutdownNow();
            if (debugEnabled) {
                log.debug("destroy({})[{}] - shutdown executor service - runners count={}",
                        channel, this, runners.size());
            }
        }
        this.executorService = null;
    }

    protected void onExit(int exitValue) {
        onExit(exitValue, "");
    }

    protected void onExit(int exitValue, String exitMessage) {
        Session session = getSession();
        if (cbCalled) {
            if (log.isTraceEnabled()) {
                log.trace("onExit({})[{}] ignore exitValue={}, message={} - already called",
                        session, this, exitValue, exitMessage);
            }
            return;
        }

        ExitCallback cb = getExitCallback();
        try {
            if (log.isDebugEnabled()) {
                log.debug("onExit({})[{}] exiting - value={}, message={}",
                        session, this, exitValue, exitMessage);
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
