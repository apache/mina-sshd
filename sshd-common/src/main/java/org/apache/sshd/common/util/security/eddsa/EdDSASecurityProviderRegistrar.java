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

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ReflectionUtils;
import org.apache.sshd.common.util.security.AbstractSecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityUtils;
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
        if (!super.isEnabled()) {
            return false;
        }

        // For backward compatibility
        return this.getBooleanProperty(SecurityUtils.EDDSA_SUPPORTED_PROP, true);
    }

    @Override
    public Provider getSecurityProvider() {
        try {
            return getOrCreateProvider(PROVIDER_CLASS);
        } catch (ReflectiveOperationException t) {
            Throwable e = GenericUtils.peelException(t);
            log.error("getSecurityProvider({}) failed ({}) to instantiate {}: {}",
                    getName(), e.getClass().getSimpleName(), PROVIDER_CLASS, e.getMessage());
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean isSecurityEntitySupported(Class<?> entityType, String name) {
        if (!isSupported()) {
            return false;
        }

        if (KeyPairGenerator.class.isAssignableFrom(entityType)
                || KeyFactory.class.isAssignableFrom(entityType)) {
            return Objects.compare(name, getName(), String.CASE_INSENSITIVE_ORDER) == 0;
        } else if (Signature.class.isAssignableFrom(entityType)) {
            return Objects.compare(SecurityUtils.CURVE_ED25519_SHA512, name, String.CASE_INSENSITIVE_ORDER) == 0;
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

            ClassLoader cl = ThreadUtils.resolveDefaultClassLoader(getClass());
            supported = ReflectionUtils.isClassAvailable(cl, "net.i2p.crypto.eddsa.EdDSAKey");
            supportHolder.set(supported);
        }

        return supported.booleanValue();
    }
}
