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
import java.security.Provider;
import java.security.Signature;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.security.AbstractSecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityEntityFactory;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class EdDSASecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {

    public static final String PROVIDER_CLASS = "net.i2p.crypto.eddsa.EdDSASecurityProvider";
    // Do not define a static registrar instance to minimize class loading issues
    private final AtomicReference<Boolean> supportHolder = new AtomicReference<>(null);

    public EdDSASecurityProviderRegistrar() {
        super(SecurityUtils.EDDSA);
    }

    @Override
    public boolean isEnabled() {
        return !SecurityUtils.isFipsMode() && super.isEnabled();
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

            Class<?> clazz = ThreadUtils.resolveDefaultClass(getClass(), "net.i2p.crypto.eddsa.EdDSAKey");
            supported = clazz != null;
            supportHolder.set(supported);
        }

        return supported.booleanValue();
    }

    @Override
    public <F> SecurityEntityFactory<F> getFactory(Class<F> entityType) throws ReflectiveOperationException {
        // Return factories that map the algorithm names to the non-standard ones used by net.i2p.
        // That way the rest of our code can work with the standard names.
        if (KeyPairGenerator.class.isAssignableFrom(entityType) || KeyFactory.class.isAssignableFrom(entityType)) {
            return new DelegatingSecurityEntityFactory<F>(super.getFactory(entityType)) {

                @Override
                protected String effectiveAlgorithm(String originalAlgorithm) {
                    if (SecurityUtils.ED25519.equalsIgnoreCase(originalAlgorithm)) {
                        return "EdDSA";
                    }
                    return originalAlgorithm;
                }
            };
        } else if (Signature.class.isAssignableFrom(entityType)) {
            return new DelegatingSecurityEntityFactory<F>(super.getFactory(entityType)) {

                @Override
                protected String effectiveAlgorithm(String originalAlgorithm) {
                    if (SecurityUtils.ED25519.equalsIgnoreCase(originalAlgorithm)) {
                        return "NONEwithEdDSA";
                    }
                    return originalAlgorithm;
                }
            };
        }
        return super.getFactory(entityType);
    }

    @Override
    public Optional<EdDSASupport> getEdDSASupport() {
        if (!isSupported()) {
            return Optional.empty();
        }
        return Optional.of(new NetI2pCryptoEdDSASupport());
    }

    private static abstract class DelegatingSecurityEntityFactory<F> implements SecurityEntityFactory<F> {

        private SecurityEntityFactory<F> delegate;

        DelegatingSecurityEntityFactory(SecurityEntityFactory<F> delegate) {
            this.delegate = delegate;
        }

        @Override
        public Class<F> getEntityType() {
            return delegate.getEntityType();
        }

        @Override
        public F getInstance(String algorithm) throws GeneralSecurityException {
            return delegate.getInstance(effectiveAlgorithm(algorithm));
        }

        protected abstract String effectiveAlgorithm(String originalAlgorithm);

        @Override
        public String toString() {
            return delegate.toString();
        }
    }

}
