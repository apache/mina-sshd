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
package org.apache.sshd.common.helpers;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.AttributeStore;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SyspropsMapWrapper;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.config.VersionProperties;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.forward.TcpipForwarderFactory;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.kex.AbstractKexFactoryManager;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.helpers.AbstractSessionFactory;
import org.apache.sshd.common.session.helpers.SessionTimeoutListener;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.forward.ForwardingFilter;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractFactoryManager extends AbstractKexFactoryManager implements FactoryManager {

    protected IoServiceFactoryFactory ioServiceFactoryFactory;
    protected IoServiceFactory ioServiceFactory;
    protected Factory<Random> randomFactory;
    protected List<NamedFactory<Channel>> channelFactories;
    protected SshAgentFactory agentFactory;
    protected ScheduledExecutorService executor;
    protected boolean shutdownExecutor;
    protected TcpipForwarderFactory tcpipForwarderFactory;
    protected ForwardingFilter tcpipForwardingFilter;
    protected FileSystemFactory fileSystemFactory;
    protected List<ServiceFactory> serviceFactories;
    protected List<RequestHandler<ConnectionService>> globalRequestHandlers;
    protected SessionTimeoutListener sessionTimeoutListener;
    protected ScheduledFuture<?> timeoutListenerFuture;
    protected final Collection<SessionListener> sessionListeners = new CopyOnWriteArraySet<>();
    protected final SessionListener sessionListenerProxy;
    protected final Collection<ChannelListener> channelListeners = new CopyOnWriteArraySet<>();
    protected final ChannelListener channelListenerProxy;

    private final Map<String, Object> properties = new ConcurrentHashMap<>();
    private final Map<AttributeKey<?>, Object> attributes = new ConcurrentHashMap<>();
    private PropertyResolver parentResolver = SyspropsMapWrapper.SYSPROPS_RESOLVER;
    private ReservedSessionMessagesHandler reservedSessionMessagesHandler;

    protected AbstractFactoryManager() {
        ClassLoader loader = getClass().getClassLoader();
        sessionListenerProxy = EventListenerUtils.proxyWrapper(SessionListener.class, loader, sessionListeners);
        channelListenerProxy = EventListenerUtils.proxyWrapper(ChannelListener.class, loader, channelListeners);
    }

    @Override
    public IoServiceFactory getIoServiceFactory() {
        synchronized (ioServiceFactoryFactory) {
            if (ioServiceFactory == null) {
                ioServiceFactory = ioServiceFactoryFactory.create(this);
            }
        }
        return ioServiceFactory;
    }

    public IoServiceFactoryFactory getIoServiceFactoryFactory() {
        return ioServiceFactoryFactory;
    }

    public void setIoServiceFactoryFactory(IoServiceFactoryFactory ioServiceFactory) {
        this.ioServiceFactoryFactory = ioServiceFactory;
    }

    @Override
    public Factory<Random> getRandomFactory() {
        return randomFactory;
    }

    public void setRandomFactory(Factory<Random> randomFactory) {
        this.randomFactory = randomFactory;
    }

    @Override
    public Map<String, Object> getProperties() {
        return properties;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(AttributeKey<T> key) {
        return (T) attributes.get(ValidateUtils.checkNotNull(key, "No key"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T setAttribute(AttributeKey<T> key, T value) {
        return (T) attributes.put(
                ValidateUtils.checkNotNull(key, "No key"),
                ValidateUtils.checkNotNull(value, "No value"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T removeAttribute(AttributeKey<T> key) {
        return (T) attributes.remove(ValidateUtils.checkNotNull(key, "No key"));
    }

    @Override
    public <T> T resolveAttribute(AttributeKey<T> key) {
        return AttributeStore.Utils.resolveAttribute(this, key);
    }

    @Override
    public PropertyResolver getParentPropertyResolver() {
        return parentResolver;
    }

    public void setParentPropertyResolver(PropertyResolver parent) {
        parentResolver = parent;
    }

    @Override
    public String getVersion() {
        return PropertyResolverUtils.getStringProperty(VersionProperties.getVersionProperties(), "sshd-version", DEFAULT_VERSION).toUpperCase();
    }

    @Override
    public List<NamedFactory<Channel>> getChannelFactories() {
        return channelFactories;
    }

    public void setChannelFactories(List<NamedFactory<Channel>> channelFactories) {
        this.channelFactories = channelFactories;
    }

    public int getNioWorkers() {
        int nb = PropertyResolverUtils.getIntProperty(this, NIO_WORKERS, DEFAULT_NIO_WORKERS);
        if (nb > 0) {
            return nb;
        } else {    // it may have been configured to a negative value
            return DEFAULT_NIO_WORKERS;
        }
    }

    public void setNioWorkers(int nioWorkers) {
        if (nioWorkers > 0) {
            PropertyResolverUtils.updateProperty(this, NIO_WORKERS, nioWorkers);
        } else {
            PropertyResolverUtils.updateProperty(this, NIO_WORKERS, null);
        }
    }

    @Override
    public SshAgentFactory getAgentFactory() {
        return agentFactory;
    }

    public void setAgentFactory(SshAgentFactory agentFactory) {
        this.agentFactory = agentFactory;
    }

    @Override
    public ScheduledExecutorService getScheduledExecutorService() {
        return executor;
    }

    public void setScheduledExecutorService(ScheduledExecutorService executor) {
        setScheduledExecutorService(executor, false);
    }

    public void setScheduledExecutorService(ScheduledExecutorService executor, boolean shutdownExecutor) {
        this.executor = executor;
        this.shutdownExecutor = shutdownExecutor;
    }

    @Override
    public TcpipForwarderFactory getTcpipForwarderFactory() {
        return tcpipForwarderFactory;
    }

    public void setTcpipForwarderFactory(TcpipForwarderFactory tcpipForwarderFactory) {
        this.tcpipForwarderFactory = tcpipForwarderFactory;
    }

    @Override
    public ForwardingFilter getTcpipForwardingFilter() {
        return tcpipForwardingFilter;
    }

    public void setTcpipForwardingFilter(ForwardingFilter tcpipForwardingFilter) {
        this.tcpipForwardingFilter = tcpipForwardingFilter;
    }

    @Override
    public FileSystemFactory getFileSystemFactory() {
        return fileSystemFactory;
    }

    public void setFileSystemFactory(FileSystemFactory fileSystemFactory) {
        this.fileSystemFactory = fileSystemFactory;
    }

    @Override
    public List<ServiceFactory> getServiceFactories() {
        return serviceFactories;
    }

    public void setServiceFactories(List<ServiceFactory> serviceFactories) {
        this.serviceFactories = serviceFactories;
    }

    @Override
    public List<RequestHandler<ConnectionService>> getGlobalRequestHandlers() {
        return globalRequestHandlers;
    }

    public void setGlobalRequestHandlers(List<RequestHandler<ConnectionService>> globalRequestHandlers) {
        this.globalRequestHandlers = globalRequestHandlers;
    }

    @Override
    public ReservedSessionMessagesHandler getReservedSessionMessagesHandler() {
        return reservedSessionMessagesHandler;
    }

    @Override
    public void setReservedSessionMessagesHandler(ReservedSessionMessagesHandler handler) {
        reservedSessionMessagesHandler = handler;
    }

    @Override
    public void addSessionListener(SessionListener listener) {
        ValidateUtils.checkNotNull(listener, "addSessionListener(%s) null instance", this);
        // avoid race conditions on notifications while manager is being closed
        if (!isOpen()) {
            log.warn("addSessionListener({})[{}] ignore registration while manager is closing", this, listener);
            return;
        }

        if (this.sessionListeners.add(listener)) {
            log.trace("addSessionListener({})[{}] registered", this, listener);
        } else {
            log.trace("addSessionListener({})[{}] ignored duplicate", this, listener);
        }
    }

    @Override
    public void removeSessionListener(SessionListener listener) {
        if (this.sessionListeners.remove(listener)) {
            log.trace("removeSessionListener({})[{}] removed", this, listener);
        } else {
            log.trace("removeSessionListener({})[{}] not registered", this, listener);
        }
    }

    @Override
    public SessionListener getSessionListenerProxy() {
        return sessionListenerProxy;
    }

    @Override
    public void addChannelListener(ChannelListener listener) {
        ValidateUtils.checkNotNull(listener, "addChannelListener(%s) null instance", this);
        // avoid race conditions on notifications while manager is being closed
        if (!isOpen()) {
            log.warn("addChannelListener({})[{}] ignore registration while session is closing", this, listener);
            return;
        }

        if (this.channelListeners.add(listener)) {
            log.trace("addChannelListener({})[{}] registered", this, listener);
        } else {
            log.trace("addChannelListener({})[{}] ignored duplicate", this, listener);
        }
    }

    @Override
    public void removeChannelListener(ChannelListener listener) {
        if (this.channelListeners.remove(listener)) {
            log.trace("removeChannelListener({})[{}] removed", this, listener);
        } else {
            log.trace("removeChannelListener({})[{}] not registered", this, listener);
        }
    }

    @Override
    public ChannelListener getChannelListenerProxy() {
        return channelListenerProxy;
    }

    protected void setupSessionTimeout(final AbstractSessionFactory<?, ?> sessionFactory) {
        // set up the the session timeout listener and schedule it
        sessionTimeoutListener = createSessionTimeoutListener();
        addSessionListener(sessionTimeoutListener);

        timeoutListenerFuture = getScheduledExecutorService()
                .scheduleAtFixedRate(sessionTimeoutListener, 1, 1, TimeUnit.SECONDS);
    }

    protected void removeSessionTimeout(final AbstractSessionFactory<?, ?> sessionFactory) {
        stopSessionTimeoutListener(sessionFactory);
    }

    protected SessionTimeoutListener createSessionTimeoutListener() {
        return new SessionTimeoutListener();
    }

    protected void stopSessionTimeoutListener(final AbstractSessionFactory<?, ?> sessionFactory) {
        // cancel the timeout monitoring task
        if (timeoutListenerFuture != null) {
            try {
                timeoutListenerFuture.cancel(true);
            } finally {
                timeoutListenerFuture = null;
            }
        }

        // remove the sessionTimeoutListener completely; should the SSH server/client be restarted, a new one
        // will be created.
        if (sessionTimeoutListener != null) {
            try {
                removeSessionListener(sessionTimeoutListener);
            } finally {
                sessionTimeoutListener = null;
            }
        }
    }

    protected void checkConfig() {
        ValidateUtils.checkNotNullAndNotEmpty(getKeyExchangeFactories(), "KeyExchangeFactories not set");

        if (getScheduledExecutorService() == null) {
            setScheduledExecutorService(
                    ThreadUtils.newSingleThreadScheduledExecutor(this.toString() + "-timer"),
                    true);
        }

        ValidateUtils.checkNotNullAndNotEmpty(getCipherFactories(), "CipherFactories not set");
        ValidateUtils.checkNotNullAndNotEmpty(getCompressionFactories(), "CompressionFactories not set");
        ValidateUtils.checkNotNullAndNotEmpty(getMacFactories(), "MacFactories not set");

        ValidateUtils.checkNotNull(getRandomFactory(), "RandomFactory not set");

        if (getIoServiceFactoryFactory() == null) {
            setIoServiceFactoryFactory(new DefaultIoServiceFactoryFactory());
        }
    }
}
