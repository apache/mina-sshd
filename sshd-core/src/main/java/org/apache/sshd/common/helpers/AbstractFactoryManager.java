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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.ServiceFactory;
import org.apache.sshd.common.SyspropsMapWrapper;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.throttle.ChannelStreamWriterResolver;
import org.apache.sshd.common.config.VersionProperties;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.forward.ForwarderFactory;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.kex.AbstractKexFactoryManager;
import org.apache.sshd.common.random.Random;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.ReservedSessionMessagesHandler;
import org.apache.sshd.common.session.SessionDisconnectHandler;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.session.UnknownChannelReferenceHandler;
import org.apache.sshd.common.session.helpers.AbstractSessionFactory;
import org.apache.sshd.common.session.helpers.SessionTimeoutListener;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.forward.ForwardingFilter;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractFactoryManager extends AbstractKexFactoryManager implements FactoryManager {
    protected IoServiceFactoryFactory ioServiceFactoryFactory;
    protected IoServiceFactory ioServiceFactory;
    protected Factory<Random> randomFactory;
    protected List<ChannelFactory> channelFactories;
    protected SshAgentFactory agentFactory;
    protected ScheduledExecutorService executor;
    protected boolean shutdownExecutor;
    protected ForwarderFactory forwarderFactory;
    protected ForwardingFilter forwardingFilter;
    protected FileSystemFactory fileSystemFactory;
    protected List<ServiceFactory> serviceFactories;
    protected List<RequestHandler<ConnectionService>> globalRequestHandlers;
    protected SessionTimeoutListener sessionTimeoutListener;
    protected ScheduledFuture<?> timeoutListenerFuture;
    protected final Collection<SessionListener> sessionListeners = new CopyOnWriteArraySet<>();
    protected final SessionListener sessionListenerProxy;
    protected final Collection<ChannelListener> channelListeners = new CopyOnWriteArraySet<>();
    protected final ChannelListener channelListenerProxy;
    protected final Collection<PortForwardingEventListener> tunnelListeners = new CopyOnWriteArraySet<>();
    protected final PortForwardingEventListener tunnelListenerProxy;

    private final Map<String, Object> properties = new ConcurrentHashMap<>();
    private final Map<AttributeRepository.AttributeKey<?>, Object> attributes = new ConcurrentHashMap<>();
    private PropertyResolver parentResolver = SyspropsMapWrapper.SYSPROPS_RESOLVER;
    private ReservedSessionMessagesHandler reservedSessionMessagesHandler;
    private SessionDisconnectHandler sessionDisconnectHandler;
    private ChannelStreamWriterResolver channelStreamWriterResolver;
    private UnknownChannelReferenceHandler unknownChannelReferenceHandler;
    private IoServiceEventListener eventListener;

    protected AbstractFactoryManager() {
        sessionListenerProxy = EventListenerUtils.proxyWrapper(SessionListener.class, sessionListeners);
        channelListenerProxy = EventListenerUtils.proxyWrapper(ChannelListener.class, channelListeners);
        tunnelListenerProxy = EventListenerUtils.proxyWrapper(PortForwardingEventListener.class, tunnelListeners);
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
    public IoServiceEventListener getIoServiceEventListener() {
        return eventListener;
    }

    @Override
    public void setIoServiceEventListener(IoServiceEventListener listener) {
        eventListener = listener;
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
    public int getAttributesCount() {
        return attributes.size();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(AttributeRepository.AttributeKey<T> key) {
        return (T) attributes.get(Objects.requireNonNull(key, "No key"));
    }

    @Override
    public Collection<AttributeKey<?>> attributeKeys() {
        return attributes.isEmpty() ? Collections.emptySet() : new HashSet<>(attributes.keySet());
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public <T> T computeAttributeIfAbsent(
            AttributeRepository.AttributeKey<T> key,
            Function<? super AttributeRepository.AttributeKey<T>, ? extends T> resolver) {
        return (T) attributes.computeIfAbsent(Objects.requireNonNull(key, "No key"), (Function) resolver);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T setAttribute(AttributeRepository.AttributeKey<T> key, T value) {
        return (T) attributes.put(
                Objects.requireNonNull(key, "No key"),
                Objects.requireNonNull(value, "No value"));
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T removeAttribute(AttributeRepository.AttributeKey<T> key) {
        return (T) attributes.remove(Objects.requireNonNull(key, "No key"));
    }

    @Override
    public void clearAttributes() {
        attributes.clear();
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
        String version = PropertyResolverUtils.getStringProperty(
                VersionProperties.getVersionProperties(),
                VersionProperties.REPORTED_VERSION, FactoryManager.DEFAULT_VERSION);
        return version.toUpperCase();
    }

    @Override
    public List<ChannelFactory> getChannelFactories() {
        return channelFactories;
    }

    public void setChannelFactories(List<ChannelFactory> channelFactories) {
        this.channelFactories = channelFactories;
    }

    public int getNioWorkers() {
        return CoreModuleProperties.NIO_WORKERS.getRequired(this);
    }

    public void setNioWorkers(int nioWorkers) {
        CoreModuleProperties.NIO_WORKERS.set(this, nioWorkers);
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
    public ForwarderFactory getForwarderFactory() {
        return forwarderFactory;
    }

    public void setForwarderFactory(ForwarderFactory forwarderFactory) {
        this.forwarderFactory = forwarderFactory;
    }

    @Override
    public ForwardingFilter getForwardingFilter() {
        return forwardingFilter;
    }

    public void setForwardingFilter(ForwardingFilter forwardingFilter) {
        this.forwardingFilter = forwardingFilter;
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
    public SessionDisconnectHandler getSessionDisconnectHandler() {
        return sessionDisconnectHandler;
    }

    @Override
    public void setSessionDisconnectHandler(SessionDisconnectHandler sessionDisconnectHandler) {
        this.sessionDisconnectHandler = sessionDisconnectHandler;
    }

    @Override
    public ChannelStreamWriterResolver getChannelStreamWriterResolver() {
        return channelStreamWriterResolver;
    }

    @Override
    public void setChannelStreamWriterResolver(ChannelStreamWriterResolver resolver) {
        channelStreamWriterResolver = resolver;
    }

    @Override
    public UnknownChannelReferenceHandler getUnknownChannelReferenceHandler() {
        return unknownChannelReferenceHandler;
    }

    @Override
    public void setUnknownChannelReferenceHandler(UnknownChannelReferenceHandler unknownChannelReferenceHandler) {
        this.unknownChannelReferenceHandler = unknownChannelReferenceHandler;
    }

    @Override
    public UnknownChannelReferenceHandler resolveUnknownChannelReferenceHandler() {
        return getUnknownChannelReferenceHandler();
    }

    @Override
    public void addSessionListener(SessionListener listener) {
        SessionListener.validateListener(listener);

        // avoid race conditions on notifications while manager is being closed
        if (!isOpen()) {
            log.warn("addSessionListener({})[{}] ignore registration while manager is closing", this, listener);
            return;
        }

        if (this.sessionListeners.add(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("addSessionListener({})[{}] registered", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("addSessionListener({})[{}] ignored duplicate", this, listener);
            }
        }
    }

    @Override
    public void removeSessionListener(SessionListener listener) {
        if (listener == null) {
            return;
        }

        SessionListener.validateListener(listener);

        if (this.sessionListeners.remove(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("removeSessionListener({})[{}] removed", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("removeSessionListener({})[{}] not registered", this, listener);
            }
        }
    }

    @Override
    public SessionListener getSessionListenerProxy() {
        return sessionListenerProxy;
    }

    @Override
    public void addChannelListener(ChannelListener listener) {
        ChannelListener.validateListener(listener);

        // avoid race conditions on notifications while manager is being closed
        if (!isOpen()) {
            log.warn("addChannelListener({})[{}] ignore registration while session is closing", this, listener);
            return;
        }

        if (this.channelListeners.add(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("addChannelListener({})[{}] registered", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("addChannelListener({})[{}] ignored duplicate", this, listener);
            }
        }
    }

    @Override
    public void removeChannelListener(ChannelListener listener) {
        if (listener == null) {
            return;
        }

        ChannelListener.validateListener(listener);
        if (this.channelListeners.remove(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("removeChannelListener({})[{}] removed", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("removeChannelListener({})[{}] not registered", this, listener);
            }
        }
    }

    @Override
    public ChannelListener getChannelListenerProxy() {
        return channelListenerProxy;
    }

    @Override
    public PortForwardingEventListener getPortForwardingEventListenerProxy() {
        return tunnelListenerProxy;
    }

    @Override
    public void addPortForwardingEventListener(PortForwardingEventListener listener) {
        PortForwardingEventListener.validateListener(listener);

        // avoid race conditions on notifications while session is being closed
        if (!isOpen()) {
            log.warn("addPortForwardingEventListener({})[{}] ignore registration while session is closing", this, listener);
            return;
        }

        if (this.tunnelListeners.add(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("addPortForwardingEventListener({})[{}] registered", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("addPortForwardingEventListener({})[{}] ignored duplicate", this, listener);
            }
        }
    }

    @Override
    public void removePortForwardingEventListener(PortForwardingEventListener listener) {
        if (listener == null) {
            return;
        }

        PortForwardingEventListener.validateListener(listener);
        if (this.tunnelListeners.remove(listener)) {
            if (log.isTraceEnabled()) {
                log.trace("removePortForwardingEventListener({})[{}] removed", this, listener);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("removePortForwardingEventListener({})[{}] not registered", this, listener);
            }
        }
    }

    protected void setupSessionTimeout(AbstractSessionFactory<?, ?> sessionFactory) {
        // set up the the session timeout listener and schedule it
        sessionTimeoutListener = createSessionTimeoutListener();
        addSessionListener(sessionTimeoutListener);

        timeoutListenerFuture = getScheduledExecutorService()
                .scheduleAtFixedRate(sessionTimeoutListener, 1, 1, TimeUnit.SECONDS);
    }

    protected void removeSessionTimeout(AbstractSessionFactory<?, ?> sessionFactory) {
        stopSessionTimeoutListener(sessionFactory);
    }

    protected SessionTimeoutListener createSessionTimeoutListener() {
        return new SessionTimeoutListener();
    }

    protected void stopSessionTimeoutListener(AbstractSessionFactory<?, ?> sessionFactory) {
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

        Objects.requireNonNull(getRandomFactory(), "RandomFactory not set");

        if (getIoServiceFactoryFactory() == null) {
            IoServiceFactoryFactory defaultFactory = DefaultIoServiceFactoryFactory.getDefaultIoServiceFactoryFactoryInstance();
            setIoServiceFactoryFactory(defaultFactory);
        }
    }
}
