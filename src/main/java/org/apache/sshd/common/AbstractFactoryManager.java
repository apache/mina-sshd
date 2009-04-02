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

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @version $Rev$, $Date$
 */
public abstract class AbstractFactoryManager implements FactoryManager {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private Map<String,String> properties = new HashMap<String,String>();
    private List<NamedFactory<KeyExchange>> keyExchangeFactories;
    private List<NamedFactory<Cipher>> cipherFactories;
    private List<NamedFactory<Compression>> compressionFactories;
    private List<NamedFactory<Mac>> macFactories;
    private List<NamedFactory<Signature>> signatureFactories;
    private NamedFactory<Random> randomFactory;
    private KeyPairProvider keyPairProvider;
    private String version;

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

    public NamedFactory<Random> getRandomFactory() {
        return randomFactory;
    }

    public void setRandomFactory(NamedFactory<Random> randomFactory) {
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
}
