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
package org.apache.sshd.server.scp;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.scp.ScpFileOpener;
import org.apache.sshd.common.scp.ScpFileOpenerHolder;
import org.apache.sshd.common.scp.ScpHelper;
import org.apache.sshd.common.scp.ScpTransferEventListener;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.ObjectBuilder;
import org.apache.sshd.common.util.threads.ExecutorServiceConfigurer;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.CommandFactory;

/**
 * This <code>CommandFactory</code> can be used as a standalone command factory
 * or can be used to augment another <code>CommandFactory</code> and provides
 * <code>SCP</code> support.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see ScpCommand
 */
public class ScpCommandFactory implements ScpFileOpenerHolder, CommandFactory, Cloneable, ExecutorServiceConfigurer {
    /**
     * A useful {@link ObjectBuilder} for {@link ScpCommandFactory}
     */
    public static class Builder implements ObjectBuilder<ScpCommandFactory> {
        private final ScpCommandFactory factory = new ScpCommandFactory();

        public Builder() {
            super();
        }

        public Builder withFileOpener(ScpFileOpener opener) {
            factory.setScpFileOpener(opener);
            return this;
        }

        public Builder withDelegate(CommandFactory delegate) {
            factory.setDelegateCommandFactory(delegate);
            return this;
        }

        public Builder withExecutorService(ExecutorService service) {
            factory.setExecutorService(service);
            return this;
        }

        public Builder withShutdownOnExit(boolean shutdown) {
            factory.setShutdownOnExit(shutdown);
            return this;
        }

        public Builder withSendBufferSize(int sendSize) {
            factory.setSendBufferSize(sendSize);
            return this;
        }

        public Builder withReceiveBufferSize(int receiveSize) {
            factory.setReceiveBufferSize(receiveSize);
            return this;
        }

        public Builder addEventListener(ScpTransferEventListener listener) {
            factory.addEventListener(listener);
            return this;
        }

        public Builder removeEventListener(ScpTransferEventListener listener) {
            factory.removeEventListener(listener);
            return this;
        }

        @Override
        public ScpCommandFactory build() {
            return factory.clone();
        }
    }

    /*
     * NOTE: we expose setters since there is no problem to change these settings between
     * successive invocations of the 'createCommand' method
     */
    private CommandFactory delegate;
    private ExecutorService executors;
    private boolean shutdownExecutor;
    private ScpFileOpener fileOpener;
    private int sendBufferSize = ScpHelper.MIN_SEND_BUFFER_SIZE;
    private int receiveBufferSize = ScpHelper.MIN_RECEIVE_BUFFER_SIZE;
    private Collection<ScpTransferEventListener> listeners = new CopyOnWriteArraySet<>();
    private ScpTransferEventListener listenerProxy;

    public ScpCommandFactory() {
        listenerProxy = EventListenerUtils.proxyWrapper(ScpTransferEventListener.class, getClass().getClassLoader(), listeners);
    }

    @Override
    public ScpFileOpener getScpFileOpener() {
        return fileOpener;
    }

    @Override
    public void setScpFileOpener(ScpFileOpener fileOpener) {
        this.fileOpener = fileOpener;
    }

    public CommandFactory getDelegateCommandFactory() {
        return delegate;
    }

    /**
     * @param factory A {@link CommandFactory} to be used if the
     *                command is not an SCP one. If {@code null} then an {@link IllegalArgumentException}
     *                will be thrown when attempting to invoke {@link #createCommand(String)}
     *                with a non-SCP command
     */
    public void setDelegateCommandFactory(CommandFactory factory) {
        delegate = factory;
    }

    @Override
    public ExecutorService getExecutorService() {
        return executors;
    }

    /**
     * @param service An {@link ExecutorService} to be used when
     *                starting {@link ScpCommand} execution. If {@code null} then a single-threaded
     *                ad-hoc service is used. <B>Note:</B> the service will <U>not</U> be shutdown
     *                when the command is terminated - unless it is the ad-hoc service, which will be
     *                shutdown regardless
     */
    @Override
    public void setExecutorService(ExecutorService service) {
        executors = service;
    }

    @Override
    public boolean isShutdownOnExit() {
        return shutdownExecutor;
    }

    @Override
    public void setShutdownOnExit(boolean shutdown) {
        shutdownExecutor = shutdown;
    }

    public int getSendBufferSize() {
        return sendBufferSize;
    }

    /**
     * @param sendSize Size (in bytes) of buffer to use when sending files
     * @see ScpHelper#MIN_SEND_BUFFER_SIZE
     */
    public void setSendBufferSize(int sendSize) {
        if (sendSize < ScpHelper.MIN_SEND_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpCommandFactory>() send buffer size "
                    + "(" + sendSize + ") below minimum required (" + ScpHelper.MIN_SEND_BUFFER_SIZE + ")");
        }
        sendBufferSize = sendSize;
    }

    public int getReceiveBufferSize() {
        return receiveBufferSize;
    }

    /**
     * @param receiveSize Size (in bytes) of buffer to use when receiving files
     * @see ScpHelper#MIN_RECEIVE_BUFFER_SIZE
     */
    public void setReceiveBufferSize(int receiveSize) {
        if (receiveSize < ScpHelper.MIN_RECEIVE_BUFFER_SIZE) {
            throw new IllegalArgumentException("<ScpCommandFactory>() receive buffer size "
                    + "(" + receiveSize + ") below minimum required (" + ScpHelper.MIN_RECEIVE_BUFFER_SIZE + ")");
        }
        receiveBufferSize = receiveSize;
    }

    /**
     * @param listener The {@link ScpTransferEventListener} to add
     * @return {@code true} if this is a <U>new</U> listener instance,
     * {@code false} if the listener is already registered
     * @throws IllegalArgumentException if {@code null} listener
     */
    public boolean addEventListener(ScpTransferEventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("No listener instance");
        }

        return listeners.add(listener);
    }

    /**
     * @param listener The {@link ScpTransferEventListener} to remove
     * @return {@code true} if the listener was registered and removed,
     * {@code false} if the listener was not registered to begin with
     * @throws IllegalArgumentException if {@code null} listener
     */
    public boolean removeEventListener(ScpTransferEventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("No listener instance");
        }

        return listeners.remove(listener);
    }

    /**
     * Parses a command string and verifies that the basic syntax is
     * correct. If parsing fails the responsibility is delegated to
     * the configured {@link CommandFactory} instance; if one exist.
     *
     * @param command command to parse
     * @return configured {@link Command} instance
     * @throws IllegalArgumentException if not an SCP command and no
     *                                  delegate command factory is available
     * @see ScpHelper#SCP_COMMAND_PREFIX
     */
    @Override
    public Command createCommand(String command) {
        if (command.startsWith(ScpHelper.SCP_COMMAND_PREFIX)) {
            return new ScpCommand(command,
                    getExecutorService(), isShutdownOnExit(),
                    getSendBufferSize(), getReceiveBufferSize(),
                    getScpFileOpener(), listenerProxy);
        }

        CommandFactory factory = getDelegateCommandFactory();
        if (factory != null) {
            return factory.createCommand(command);
        }

        throw new IllegalArgumentException("Unknown command, does not begin with '" + ScpHelper.SCP_COMMAND_PREFIX + "': " + command);
    }

    @Override
    public ScpCommandFactory clone() {
        try {
            ScpCommandFactory other = getClass().cast(super.clone());
            // clone the listeners set as well
            other.listeners = this.listeners.isEmpty()
                    ? new CopyOnWriteArraySet<ScpTransferEventListener>()
                    : new CopyOnWriteArraySet<>(this.listeners);
            other.listenerProxy = EventListenerUtils.proxyWrapper(ScpTransferEventListener.class, getClass().getClassLoader(), other.listeners);
            return other;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);    // un-expected...
        }
    }
}
