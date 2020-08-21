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
package org.apache.sshd.scp.server;

import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Supplier;

import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ObjectBuilder;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ManagedExecutorServiceSupplier;
import org.apache.sshd.scp.common.ScpFileOpener;
import org.apache.sshd.scp.common.ScpFileOpenerHolder;
import org.apache.sshd.scp.common.ScpHelper;
import org.apache.sshd.scp.common.ScpTransferEventListener;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.AbstractDelegatingCommandFactory;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.shell.InteractiveProcessShellFactory;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.server.shell.ShellFactorySelector;

/**
 * This <code>CommandFactory</code> can be used as a standalone command factory or can be used to augment another
 * <code>CommandFactory</code> and provides <code>SCP</code> support.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    ScpCommand
 * @see    ScpShell
 */
public class ScpCommandFactory
        extends AbstractDelegatingCommandFactory
        implements ManagedExecutorServiceSupplier, ScpFileOpenerHolder, Cloneable, ShellFactory, ShellFactorySelector {

    public static final String SCP_FACTORY_NAME = "scp";

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

        public Builder withExecutorServiceProvider(
                Supplier<? extends CloseableExecutorService> provider) {
            factory.setExecutorServiceProvider(provider);
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

        public Builder withDelegateShellFactory(ShellFactory shellFactory) {
            factory.setDelegateShellFactory(shellFactory);
            return this;
        }

        @Override
        public ScpCommandFactory build() {
            return factory.clone();
        }
    }

    private Supplier<? extends CloseableExecutorService> executorsProvider;
    private ScpFileOpener fileOpener;
    private ShellFactory delegateShellFactory = InteractiveProcessShellFactory.INSTANCE;
    private int sendBufferSize = ScpHelper.DEFAULT_SEND_BUFFER_SIZE;
    private int receiveBufferSize = ScpHelper.DEFAULT_RECEIVE_BUFFER_SIZE;
    private Collection<ScpTransferEventListener> listeners = new CopyOnWriteArraySet<>();
    private ScpTransferEventListener listenerProxy;

    public ScpCommandFactory() {
        super(SCP_FACTORY_NAME);
        listenerProxy = EventListenerUtils.proxyWrapper(ScpTransferEventListener.class, listeners);
    }

    @Override
    public ScpFileOpener getScpFileOpener() {
        return fileOpener;
    }

    @Override
    public void setScpFileOpener(ScpFileOpener fileOpener) {
        this.fileOpener = fileOpener;
    }

    @Override
    public Supplier<? extends CloseableExecutorService> getExecutorServiceProvider() {
        return executorsProvider;
    }

    @Override
    public void setExecutorServiceProvider(
            Supplier<? extends CloseableExecutorService> provider) {
        executorsProvider = provider;
    }

    public int getSendBufferSize() {
        return sendBufferSize;
    }

    /**
     * @param sendSize Size (in bytes) of buffer to use when sending files
     * @see            ScpHelper#MIN_SEND_BUFFER_SIZE
     */
    public void setSendBufferSize(int sendSize) {
        if (sendSize < ScpHelper.MIN_SEND_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "<ScpCommandFactory>() send buffer size "
                                               + "(" + sendSize + ") below minimum required (" + ScpHelper.MIN_SEND_BUFFER_SIZE
                                               + ")");
        }
        sendBufferSize = sendSize;
    }

    public int getReceiveBufferSize() {
        return receiveBufferSize;
    }

    /**
     * @param receiveSize Size (in bytes) of buffer to use when receiving files
     * @see               ScpHelper#MIN_RECEIVE_BUFFER_SIZE
     */
    public void setReceiveBufferSize(int receiveSize) {
        if (receiveSize < ScpHelper.MIN_RECEIVE_BUFFER_SIZE) {
            throw new IllegalArgumentException(
                    "<ScpCommandFactory>() receive buffer size "
                                               + "(" + receiveSize + ") below minimum required ("
                                               + ScpHelper.MIN_RECEIVE_BUFFER_SIZE + ")");
        }
        receiveBufferSize = receiveSize;
    }

    /**
     * @param  listener                 The {@link ScpTransferEventListener} to add
     * @return                          {@code true} if this is a <U>new</U> listener instance, {@code false} if the
     *                                  listener is already registered
     * @throws IllegalArgumentException if {@code null} listener
     */
    public boolean addEventListener(ScpTransferEventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("No listener instance");
        }

        return listeners.add(listener);
    }

    /**
     * @param  listener                 The {@link ScpTransferEventListener} to remove
     * @return                          {@code true} if the listener was registered and removed, {@code false} if the
     *                                  listener was not registered to begin with
     * @throws IllegalArgumentException if {@code null} listener
     */
    public boolean removeEventListener(ScpTransferEventListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("No listener instance");
        }

        return listeners.remove(listener);
    }

    @Override
    public boolean isSupportedCommand(String command) {
        if (GenericUtils.isEmpty(command)) {
            return false;
        }

        return command.startsWith(ScpHelper.SCP_COMMAND_PREFIX);
    }

    @Override
    protected Command executeSupportedCommand(String command) {
        return new ScpCommand(
                command,
                resolveExecutorService(command),
                getSendBufferSize(), getReceiveBufferSize(),
                getScpFileOpener(), listenerProxy);
    }

    /**
     * @return The delegate {@link ShellFactory} to use if {@link #selectShellFactory(ChannelSession)} decides not to
     *         use itself as the {@link ShellFactory} - default={@link InteractiveProcessShellFactory}.
     * @see    #setDelegateShellFactory(ShellFactory)
     */
    public ShellFactory getDelegateShellFactory() {
        return delegateShellFactory;
    }

    /**
     * @param delegateShellFactory The {@link ShellFactory} to use if {@link #selectShellFactory(ChannelSession)}
     *                             decides not to use itself as the {@link ShellFactory}. If {@code null} then it will
     *                             always decide to use itself regardless of the {@link ChannelSession}
     * @see                        #selectShellFactory(ChannelSession)
     */
    public void setDelegateShellFactory(ShellFactory delegateShellFactory) {
        this.delegateShellFactory = delegateShellFactory;
    }

    @Override
    public ShellFactory selectShellFactory(ChannelSession channelSession) throws IOException {
        SessionContext session = channelSession.getSessionContext();
        String clientVersion = session.getClientVersion();
        // SSHD-1009
        if (clientVersion.contains("WinSCP")) {
            return this;
        }

        return delegateShellFactory;
    }

    @Override
    public Command createShell(ChannelSession channel) throws IOException {
        ShellFactory factory = selectShellFactory(channel);
        if ((factory == this) || (factory == null)) {
            return new ScpShell(
                    channel,
                    resolveExecutorService(),
                    getSendBufferSize(), getReceiveBufferSize(),
                    getScpFileOpener(), listenerProxy);
        } else {
            return factory.createShell(channel);
        }
    }

    protected CloseableExecutorService resolveExecutorService(String command) {
        return resolveExecutorService();
    }

    @Override
    public ScpCommandFactory clone() {
        try {
            ScpCommandFactory other = getClass().cast(super.clone());
            // clone the listeners set as well
            other.listeners = new CopyOnWriteArraySet<>(this.listeners);
            other.listenerProxy = EventListenerUtils.proxyWrapper(ScpTransferEventListener.class, other.listeners);
            return other;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e); // un-expected...
        }
    }
}
