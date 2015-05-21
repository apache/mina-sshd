/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common;

import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.io.DefaultIoServiceFactoryFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoServiceFactoryFactory;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.AbstractSessionFactory;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.SessionTimeoutListener;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractFactoryManager extends CloseableUtils.AbstractInnerCloseable implements FactoryManager {

    protected Map<String,String> properties = new HashMap<String,String>();
    protected IoServiceFactoryFactory ioServiceFactoryFactory;
    protected IoServiceFactory ioServiceFactory;
    protected List<NamedFactory<KeyExchange>> keyExchangeFactories;
    protected List<NamedFactory<Cipher>> cipherFactories;
    protected List<NamedFactory<Compression>> compressionFactories;
    protected List<NamedFactory<Mac>> macFactories;
    protected List<NamedFactory<Signature>> signatureFactories;
    protected Factory<Random> randomFactory;
    protected KeyPairProvider keyPairProvider;
    protected String version;
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

    protected AbstractFactoryManager() {
        loadVersion();
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
    public List<NamedFactory<KeyExchange>> getKeyExchangeFactories() {
        return keyExchangeFactories;
    }

    public void setKeyExchangeFactories(List<NamedFactory<KeyExchange>> keyExchangeFactories) {
        this.keyExchangeFactories = keyExchangeFactories;
    }

    @Override
    public List<NamedFactory<Cipher>> getCipherFactories() {
        return cipherFactories;
    }

    public void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories) {
        this.cipherFactories = cipherFactories;
    }

    @Override
    public List<NamedFactory<Compression>> getCompressionFactories() {
        return compressionFactories;
    }

    public void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories) {
        this.compressionFactories = compressionFactories;
    }

    @Override
    public List<NamedFactory<Mac>> getMacFactories() {
        return macFactories;
    }

    public void setMacFactories(List<NamedFactory<Mac>> macFactories) {
        this.macFactories = macFactories;
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return signatureFactories;
    }

    public void setSignatureFactories(List<NamedFactory<Signature>> signatureFactories) {
        this.signatureFactories = signatureFactories;
    }

    @Override
    public Factory<Random> getRandomFactory() {
        return randomFactory;
    }

    public void setRandomFactory(Factory<Random> randomFactory) {
        this.randomFactory = randomFactory;
    }

    @Override
    public KeyPairProvider getKeyPairProvider() {
        return keyPairProvider;
    }

    public void setKeyPairProvider(KeyPairProvider keyPairProvider) {
        this.keyPairProvider = keyPairProvider;
    }

    @Override
    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    @Override
    public String getVersion() {
        return version;
    }

    protected void loadVersion() {
        this.version = "SSHD-UNKNOWN";
        try {
            try (InputStream input = getClass().getClassLoader().getResourceAsStream("org/apache/sshd/sshd-version.properties")) {
                Properties props = new Properties();
                props.load(input);
                this.version = props.getProperty("version").toUpperCase();
            }
        } catch (Exception e) {
            log.warn("Unable to load version from resources. Missing org/apache/sshd/sshd-version.properties ?", e);
        }
    }

    @Override
    public List<NamedFactory<Channel>> getChannelFactories() {
        return channelFactories;
    }

    public void setChannelFactories(List<NamedFactory<Channel>> channelFactories) {
        this.channelFactories = channelFactories;
    }

    public int getNioWorkers() {
        int nb=FactoryManagerUtils.getIntProperty(this, NIO_WORKERS, DEFAULT_NIO_WORKERS);
        if (nb > 0) {
            return nb;
        } else {    // it may have been configured to a negative value
            return DEFAULT_NIO_WORKERS;
        }
    }

    public void setNioWorkers(int nioWorkers) {
        if (nioWorkers > 0) {
            FactoryManagerUtils.updateProperty(this, NIO_WORKERS, nioWorkers);
        } else {
            FactoryManagerUtils.updateProperty(this, NIO_WORKERS, null);
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

    protected void setupSessionTimeout(final AbstractSessionFactory sessionFactory) {
        // set up the the session timeout listener and schedule it
        sessionTimeoutListener = createSessionTimeoutListener();
        sessionFactory.addListener(sessionTimeoutListener);

        timeoutListenerFuture = getScheduledExecutorService()
                .scheduleAtFixedRate(sessionTimeoutListener, 1, 1, TimeUnit.SECONDS);
    }

    protected void removeSessionTimeout(final AbstractSessionFactory sessionFactory) {
        stopSessionTimeoutListener(sessionFactory);
    }

    protected SessionTimeoutListener createSessionTimeoutListener() {
        return new SessionTimeoutListener();
    }

    protected void stopSessionTimeoutListener(final AbstractSessionFactory sessionFactory) {
        // cancel the timeout monitoring task
        if (timeoutListenerFuture != null) {
            timeoutListenerFuture.cancel(true);
            timeoutListenerFuture = null;
        }

        // remove the sessionTimeoutListener completely; should the SSH server/client be restarted, a new one
        // will be created.
        if (sessionFactory != null && sessionTimeoutListener != null) {
            sessionFactory.removeListener(sessionTimeoutListener);
        }
        sessionTimeoutListener = null;
    }
    
    protected void checkConfig() {
        ValidateUtils.checkNotNullAndNotEmpty(getKeyExchangeFactories(), "KeyExchangeFactories not set", GenericUtils.EMPTY_OBJECT_ARRAY);

        if (getScheduledExecutorService() == null) {
            setScheduledExecutorService(
                    ThreadUtils.newSingleThreadScheduledExecutor(this.toString() + "-timer"),
                    true);
        }

        ValidateUtils.checkNotNullAndNotEmpty(getCipherFactories(), "CipherFactories not set", GenericUtils.EMPTY_OBJECT_ARRAY);
        ValidateUtils.checkNotNullAndNotEmpty(getCompressionFactories(), "CompressionFactories not set", GenericUtils.EMPTY_OBJECT_ARRAY);
        ValidateUtils.checkNotNullAndNotEmpty(getMacFactories(), "MacFactories not set", GenericUtils.EMPTY_OBJECT_ARRAY);

        ValidateUtils.checkNotNull(getRandomFactory(), "RandomFactory not set", GenericUtils.EMPTY_OBJECT_ARRAY);

        if (getIoServiceFactoryFactory() == null) {
            setIoServiceFactoryFactory(new DefaultIoServiceFactoryFactory());
        }
    }
}
