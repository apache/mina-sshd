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

package org.apache.sshd.common.kex;

import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractKexFactoryManager
              extends AbstractInnerCloseable
              implements KexFactoryManager {
    private final KexFactoryManager delegate;
    private List<NamedFactory<KeyExchange>> keyExchangeFactories;
    private List<NamedFactory<Cipher>> cipherFactories;
    private List<NamedFactory<Compression>> compressionFactories;
    private List<NamedFactory<Mac>> macFactories;
    private List<NamedFactory<Signature>> signatureFactories;

    protected AbstractKexFactoryManager() {
        this(null);
    }

    protected AbstractKexFactoryManager(KexFactoryManager delegate) {
        this.delegate = delegate;
    }

    protected KexFactoryManager getDelegate() {
        return delegate;
    }

    @Override
    public List<NamedFactory<KeyExchange>> getKeyExchangeFactories() {
        KexFactoryManager parent = getDelegate();
        return resolveEffectiveFactories(KeyExchange.class, keyExchangeFactories,
            (parent == null) ? Collections.emptyList() : parent.getKeyExchangeFactories());
    }

    @Override
    public void setKeyExchangeFactories(List<NamedFactory<KeyExchange>> keyExchangeFactories) {
        this.keyExchangeFactories = keyExchangeFactories;
    }

    @Override
    public List<NamedFactory<Cipher>> getCipherFactories() {
        KexFactoryManager parent = getDelegate();
        return resolveEffectiveFactories(Cipher.class, cipherFactories,
            (parent == null) ? Collections.emptyList() : parent.getCipherFactories());
    }

    @Override
    public void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories) {
        this.cipherFactories = cipherFactories;
    }

    @Override
    public List<NamedFactory<Compression>> getCompressionFactories() {
        KexFactoryManager parent = getDelegate();
        return resolveEffectiveFactories(Compression.class, compressionFactories,
            (parent == null) ? Collections.emptyList() : parent.getCompressionFactories());
    }

    @Override
    public void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories) {
        this.compressionFactories = compressionFactories;
    }

    @Override
    public List<NamedFactory<Mac>> getMacFactories() {
        KexFactoryManager parent = getDelegate();
        return resolveEffectiveFactories(Mac.class, macFactories,
            (parent == null) ? Collections.emptyList() : parent.getMacFactories());
    }

    @Override
    public void setMacFactories(List<NamedFactory<Mac>> macFactories) {
        this.macFactories = macFactories;
    }

    @Override
    public List<NamedFactory<Signature>> getSignatureFactories() {
        KexFactoryManager parent = getDelegate();
        return resolveEffectiveFactories(Signature.class, signatureFactories,
            (parent == null) ? Collections.emptyList() : parent.getSignatureFactories());
    }

    @Override
    public void setSignatureFactories(List<NamedFactory<Signature>> signatureFactories) {
        this.signatureFactories = signatureFactories;
    }

    protected <V> List<NamedFactory<V>> resolveEffectiveFactories(
            Class<V> factoryType, List<NamedFactory<V>> local, List<NamedFactory<V>> inherited) {
        if (GenericUtils.isEmpty(local)) {
            return inherited;
        } else {
            return local;
        }
    }

    protected <V> V resolveEffectiveProvider(Class<V> providerType, V local, V inherited) {
        if (local == null) {
            return inherited;
        } else {
            return local;
        }
    }
}
