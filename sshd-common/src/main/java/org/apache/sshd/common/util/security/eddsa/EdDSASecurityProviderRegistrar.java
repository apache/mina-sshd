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
package org.apache.sshd.common.util.security.eddsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.security.AbstractSecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityEntityFactory;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EdDSASecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {

    public static final String PROVIDER_CLASS = "net.i2p.crypto.eddsa.EdDSASecurityProvider";
    // Do not define a static registrar instance to minimize class loading issues
    private final AtomicReference<Boolean> supportHolder = new AtomicReference<>(null);

    private boolean useName = true;

    public EdDSASecurityProviderRegistrar() {
        super(SecurityUtils.EDDSA);
    }

    @Override
    public boolean isEnabled() {
        return !SecurityUtils.isFipsMode() && super.isEnabled();
    }

    @Override
    public boolean isNamedProviderUsed() {
        return useName;
    }

    @Override
    public Provider getSecurityProvider() {
        try {
            return getOrCreateProvider(PROVIDER_CLASS);
        } catch (ReflectiveOperationException t) {
            Throwable e = ExceptionUtils.peelException(t);
            log.error("getSecurityProvider({}) failed ({}) to instantiate {}: {}",
                    getName(), e.getClass().getSimpleName(), PROVIDER_CLASS, e.getMessage());
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean isSecurityEntitySupported(Class<?> entityType, String name) {
        if (!isSupported()) {
            return false;
        }

        if (KeyPairGenerator.class.isAssignableFrom(entityType)
                || KeyFactory.class.isAssignableFrom(entityType)) {
            return SecurityUtils.ED25519.equalsIgnoreCase(name);
        } else if (Signature.class.isAssignableFrom(entityType)) {
            return SecurityUtils.ED25519.equalsIgnoreCase(name);
        } else {
            return false;
        }
    }

    @Override
    public boolean isSupported() {
        Boolean supported;
        synchronized (supportHolder) {
            supported = supportHolder.get();
            if (supported != null) {
                return supported.booleanValue();
            }

            supported = Boolean.valueOf(EdDSAAccessor.INSTANCE.isSupported());
            if (supported.booleanValue()) {
                Provider provider = Security.getProvider(getProviderName());
                useName = provider != null;
            }
            supportHolder.set(supported);
        }

        return supported.booleanValue();
    }

    @Override
    protected Provider createProviderInstance(String providerClassName) throws ReflectiveOperationException {
        ValidateUtils.checkTrue(PROVIDER_CLASS.equals(providerClassName), "Unexpected class name %s", providerClassName);
        Provider result = EdDSAAccessor.INSTANCE.createProvider();
        if (result == null) {
            throw new ReflectiveOperationException("Cannot instantiate " + PROVIDER_CLASS);
        }
        return result;
    }

    @Override
    public SecurityEntityFactory getFactory() {
        return new DelegatingSecurityEntityProvider(super.getFactory());
    }

    @Override
    public PublicKey getPublicKey(PrivateKey key) {
        if (isEnabled() && isSupported() && SecurityUtils.EDDSA.equals(key.getAlgorithm())
                && key.getClass().getPackage().getName().startsWith("net.i2p.")) {
            return EdDSAPublicKeyFactory.INSTANCE.getPublicKey(key);
        }
        return super.getPublicKey(key);
    }

    private static class DelegatingSecurityEntityProvider implements SecurityEntityFactory {

        private SecurityEntityFactory delegate;

        DelegatingSecurityEntityProvider(SecurityEntityFactory delegate) {
            this.delegate = delegate;
        }

        @Override
        public KeyFactory createKeyFactory(String algorithm) throws GeneralSecurityException {
            String effective = algorithm;
            if (SecurityUtils.ED25519.equalsIgnoreCase(effective)) {
                effective = SecurityUtils.EDDSA;
            }
            return delegate.createKeyFactory(effective);
        }

        @Override
        public KeyPairGenerator createKeyPairGenerator(String algorithm) throws GeneralSecurityException {
            String effective = algorithm;
            if (SecurityUtils.ED25519.equalsIgnoreCase(effective)) {
                effective = SecurityUtils.EDDSA;
            }
            return delegate.createKeyPairGenerator(effective);
        }

        @Override
        public Signature createSignature(String algorithm) throws GeneralSecurityException {
            String effective = algorithm;
            if (SecurityUtils.ED25519.equalsIgnoreCase(effective)) {
                effective = "NONEwithEdDSA";
            }
            return delegate.createSignature(effective);
        }
    }
}
