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

import org.apache.sshd.agent.SshAgentFactory;
import org.apache.sshd.common.ForwardingAcceptorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractFactoryManager implements FactoryManager {

    private final Logger log = LoggerFactory.getLogger(getClass());

    protected Map<String,String> properties = new HashMap<String,String>();
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
    protected ForwardingAcceptorFactory tcpipForwardingAcceptorFactory;

    protected AbstractFactoryManager() {
        loadVersion();
    }

    public List<NamedFactory<KeyExchange>> getKeyExchangeFactories() {
        return keyExchangeFactories;
    }

    public void setKeyExchangeFactories(List<NamedFactory<KeyExchange>> keyExchangeFactories) {
        this.keyExchangeFactories = keyExchangeFactories;
    }

    public List<NamedFactory<Cipher>> getCipherFactories() {
        return cipherFactories;
    }

    public void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories) {
        this.cipherFactories = cipherFactories;
    }

    public List<NamedFactory<Compression>> getCompressionFactories() {
        return compressionFactories;
    }

    public void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories) {
        this.compressionFactories = compressionFactories;
    }

    public List<NamedFactory<Mac>> getMacFactories() {
        return macFactories;
    }

    public void setMacFactories(List<NamedFactory<Mac>> macFactories) {
        this.macFactories = macFactories;
    }

    public List<NamedFactory<Signature>> getSignatureFactories() {
        return signatureFactories;
    }

    public void setSignatureFactories(List<NamedFactory<Signature>> signatureFactories) {
        this.signatureFactories = signatureFactories;
    }

    public Factory<Random> getRandomFactory() {
        return randomFactory;
    }

    public void setRandomFactory(Factory<Random> randomFactory) {
        this.randomFactory = randomFactory;
    }

    public KeyPairProvider getKeyPairProvider() {
        return keyPairProvider;
    }

    public void setKeyPairProvider(KeyPairProvider keyPairProvider) {
        this.keyPairProvider = keyPairProvider;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    public String getVersion() {
        return version;
    }

    protected void loadVersion() {
        this.version = "SSHD-UNKNOWN";
        try {
            InputStream input = getClass().getClassLoader().getResourceAsStream("org/apache/sshd/sshd-version.properties");
            try {
                Properties props = new Properties();
                props.load(input);
                this.version = props.getProperty("version").toUpperCase();
            } finally {
                input.close();
            }
        } catch (Exception e) {
            log.warn("Unable to load version from resources. Missing org/apache/sshd/sshd-version.properties ?", e);
        }
    }

    public List<NamedFactory<Channel>> getChannelFactories() {
        return channelFactories;
    }

    public void setChannelFactories(List<NamedFactory<Channel>> channelFactories) {
        this.channelFactories = channelFactories;
    }

    public int getNioWorkers() {
        String nioWorkers = getProperties().get(NIO_WORKERS);
        if (nioWorkers != null && nioWorkers.length() > 0) {
            int nb = Integer.parseInt(nioWorkers);
            if (nb > 0) {
                return nb;
            }
        }
        return DEFAULT_NIO_WORKERS;
    }

    public void setNioWorkers(int nioWorkers) {
        if (nioWorkers > 0) {
            getProperties().put(NIO_WORKERS, Integer.toString(nioWorkers));
        } else {
            getProperties().remove(NIO_WORKERS);
        }
    }

    public SshAgentFactory getAgentFactory() {
        return agentFactory;
    }

    public void setAgentFactory(SshAgentFactory agentFactory) {
        this.agentFactory = agentFactory;
    }

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

    public ForwardingAcceptorFactory getTcpipForwardingAcceptorFactory() {
        return tcpipForwardingAcceptorFactory;
    }

    public void setTcpipForwardNioSocketAcceptorFactory(ForwardingAcceptorFactory f) {
        tcpipForwardingAcceptorFactory = f;
    }
}
