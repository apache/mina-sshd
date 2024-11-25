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
package org.apache.sshd.common.util.security.bouncycastle;

import java.lang.reflect.Field;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.AbstractSecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.eddsa.generic.EdDSASupport;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BouncyCastleSecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {
    // We want to use reflection API so as not to require BouncyCastle to be present in the classpath
    public static final String PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    public static final String FIPS_PROVIDER_CLASS = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
    private static final String BCFIPS_PROVIDER_NAME = "BCFIPS";
    private static final String BC_PROVIDER_NAME = "BC";
    private static final String NAME_FIELD = "PROVIDER_NAME";
    private static final String EDDSA_KEY_CLASS_NAME = "org.bouncycastle.jcajce.interfaces.EdDSAKey";

    // Do not define a static registrar instance to minimize class loading issues
    private final AtomicReference<Boolean> supportHolder = new AtomicReference<>(null);
    private final AtomicReference<String> allSupportHolder = new AtomicReference<>();
    private final AtomicReference<Boolean> edDSASupportHolder = new AtomicReference<>(null);

    private String providerClass;
    private String providerName;

    public BouncyCastleSecurityProviderRegistrar() {
        super(SecurityUtils.BOUNCY_CASTLE);
    }

    @Override
    public boolean isEnabled() {
        if (!super.isEnabled()) {
            return false;
        }

        // For backward compatibility
        return this.getBooleanProperty(SecurityUtils.REGISTER_BOUNCY_CASTLE_PROP, true);
    }

    @Override
    public String getProviderName() {
        return providerName;
    }

    @Override
    public Provider getSecurityProvider() {
        try {
            return getOrCreateProvider(providerClass);
        } catch (ReflectiveOperationException t) {
            Throwable e = ExceptionUtils.peelException(t);
            log.error("getSecurityProvider({}) failed ({}) to instantiate {}: {}",
                    getName(), e.getClass().getSimpleName(), providerClass, e.getMessage());
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            throw new IllegalStateException(e);
        }
    }

    @Override
    public String getDefaultSecurityEntitySupportValue(Class<?> entityType) {
        String allValue = allSupportHolder.get();
        if (GenericUtils.length(allValue) > 0) {
            return allValue;
        }

        String propName = getConfigurationPropertyName("supportAll");
        allValue = this.getStringProperty(propName, ALL_OPTIONS_VALUE);
        if (GenericUtils.isEmpty(allValue)) {
            allValue = NO_OPTIONS_VALUE;
        }

        allSupportHolder.set(allValue);
        return allValue;
    }

    @Override
    public boolean isSecurityEntitySupported(Class<?> entityType, String name) {
        if (!isSupported()) {
            return false;
        }

        if (KeyPairGenerator.class.isAssignableFrom(entityType)
                || KeyFactory.class.isAssignableFrom(entityType)) {
            if (Objects.compare(name, SecurityUtils.EDDSA, String.CASE_INSENSITIVE_ORDER) == 0
                    && SecurityUtils.isNetI2pCryptoEdDSARegistered()) {
                return false;
            }
        } else if (Signature.class.isAssignableFrom(entityType)) {
            if (Objects.compare(name, SecurityUtils.CURVE_ED25519_SHA512, String.CASE_INSENSITIVE_ORDER) == 0
                    && SecurityUtils.isNetI2pCryptoEdDSARegistered()) {
                return false;
            }
        }

        return super.isSecurityEntitySupported(entityType, name);
    }

    @Override
    public boolean isSupported() {
        Boolean supported;
        synchronized (supportHolder) {
            supported = supportHolder.get();
            if (supported != null) {
                return supported.booleanValue();
            }
            boolean requireFips = SecurityUtils.isFipsMode();
            Class<?> clazz = null;
            if (!requireFips) {
                clazz = ThreadUtils.resolveDefaultClass(getClass(), PROVIDER_CLASS);
            }
            if (clazz == null) {
                clazz = ThreadUtils.resolveDefaultClass(getClass(), FIPS_PROVIDER_CLASS);
            }
            if (clazz != null) {
                // Apache MINA sshd assumes that if we can get at the provider class, we can also get any other class we
                // need. However, and BC-based optional stuff should actually check if it does have the concrete
                // classes it needs accessible. The FIPS version has only a subset of the full BC.
                providerClass = clazz.getName();
                Provider provider = Security.getProvider(BCFIPS_PROVIDER_NAME);
                if (provider != null) {
                    providerName = BCFIPS_PROVIDER_NAME;
                } else if (!requireFips) {
                    provider = Security.getProvider(BC_PROVIDER_NAME);
                    if (provider != null) {
                        providerName = BC_PROVIDER_NAME;
                    }
                }
                if (providerName == null) {
                    Field f;
                    try {
                        f = clazz.getField(NAME_FIELD);
                        Object nameValue = f.get(null);
                        if (nameValue instanceof String) {
                            providerName = nameValue.toString();
                        }
                    } catch (Exception e) {
                        log.warn("Alleged Bouncy Castle class {} has no {}; ignoring this provider.", providerClass, NAME_FIELD,
                                e);
                    }
                }
                supported = Boolean.valueOf(providerName != null);
            } else {
                supported = Boolean.FALSE;
            }
            supportHolder.set(supported);
        }

        return supported.booleanValue();
    }

    @Override
    public Optional<EdDSASupport<?, ?>> getEdDSASupport() {
        if (!isEdDSASupported()) {
            return Optional.empty();
        }
        return Optional.of(new org.apache.sshd.common.util.security.eddsa.bouncycastle.BouncyCastleEdDSASupport());
    }

    private boolean isEdDSASupported() {
        if (!isSupported()) {
            return false;
        }

        Boolean edDSASupported;
        synchronized (edDSASupportHolder) {
            edDSASupported = edDSASupportHolder.get();
            if (edDSASupported != null) {
                return edDSASupported.booleanValue();
            }
            Class<?> clazz = ThreadUtils.resolveDefaultClass(getClass(), EDDSA_KEY_CLASS_NAME);
            edDSASupported = Boolean.valueOf(clazz != null);
            edDSASupportHolder.set(edDSASupported);
            return edDSASupported;
        }
    }
}
