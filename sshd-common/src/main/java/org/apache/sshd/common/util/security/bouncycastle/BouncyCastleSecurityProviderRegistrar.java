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
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.AbstractSecurityProviderRegistrar;
import org.apache.sshd.common.util.security.KEM;
import org.apache.sshd.common.util.security.SecurityEntityFactory;
import org.apache.sshd.common.util.security.SecurityUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BouncyCastleSecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {
    // We want to use reflection API so as not to require BouncyCastle to be present in the classpath
    public static final String PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    public static final String FIPS_PROVIDER_CLASS = "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
    private static final String BCFIPS_PROVIDER_NAME = "BCFIPS";
    private static final String BC_PROVIDER_NAME = "BC";

    // Do not define a static registrar instance to minimize class loading issues
    private final AtomicReference<Boolean> supportHolder = new AtomicReference<>(null);
    private final AtomicReference<String> allSupportHolder = new AtomicReference<>();
    private final AtomicReference<Boolean> edDSASupportHolder = new AtomicReference<>(null);

    private String providerClass;
    private String providerName;

    private boolean useName = true;

    public BouncyCastleSecurityProviderRegistrar() {
        super(SecurityUtils.BOUNCY_CASTLE);
    }

    @Override
    public String getProviderName() {
        return providerName;
    }

    @Override
    public boolean isNamedProviderUsed() {
        return useName;
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

        boolean supported = true;
        if (KeyPairGenerator.class.isAssignableFrom(entityType)
                || KeyFactory.class.isAssignableFrom(entityType)) {
            if (SecurityUtils.ED25519.equalsIgnoreCase(name)) {
                supported = isEdDSASupported();
            }
        } else if (Signature.class.isAssignableFrom(entityType)) {
            if (SecurityUtils.ED25519.equalsIgnoreCase(name)) {
                supported = isEdDSASupported();
            }
        } else if (KEM.class.isAssignableFrom(entityType)) {
            supported = BouncyCastleKEMAccessor.INSTANCE.isSupported();
            supported = supported && BouncyCastleKEM.INSTANCE.isSupported(name);
        }

        return supported && super.isSecurityEntitySupported(entityType, name);
    }

    @Override
    public SecurityEntityFactory getFactory() {
        if (isNamedProviderUsed()) {
            return new SecurityEntityFactory.Named(getProviderName()) {

                @Override
                public KEM createKEM(String algorithm) throws GeneralSecurityException {
                    return BouncyCastleKEM.INSTANCE.get(algorithm);
                }
            };
        }
        return new SecurityEntityFactory.ByProvider(getSecurityProvider()) {

            @Override
            public KEM createKEM(String algorithm) throws GeneralSecurityException {
                return BouncyCastleKEM.INSTANCE.get(algorithm);
            }
        };
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
            if (requireFips) {
                // Apache MINA sshd assumes that if we can get at the provider class, we can also get any other class we
                // need. However, and BC-based optional stuff should actually check if it does have the concrete
                // classes it needs accessible. The FIPS version has only a subset of the full BC.
                if (BouncyCastleAccessor.INSTANCE.getProviderClass(FIPS_PROVIDER_CLASS) == null) {
                    supported = Boolean.FALSE;
                } else {
                    providerClass = FIPS_PROVIDER_CLASS;
                    providerName = BCFIPS_PROVIDER_NAME;
                    supported = Boolean.TRUE;
                }
            } else {
                // Check first what providers we have installed in the system. We also need to be able to load classes
                // from there, so check if we can load the class.
                boolean fipsInstalled = Security.getProvider(BCFIPS_PROVIDER_NAME) != null;
                boolean bcInstalled = Security.getProvider(BC_PROVIDER_NAME) != null;
                boolean haveFips = BouncyCastleAccessor.INSTANCE.getProviderClass(FIPS_PROVIDER_CLASS) != null;
                boolean haveBc = BouncyCastleAccessor.INSTANCE.getProviderClass(PROVIDER_CLASS) != null;
                if (fipsInstalled && haveFips) {
                    providerClass = FIPS_PROVIDER_CLASS;
                    providerName = BCFIPS_PROVIDER_NAME;
                    useName = true;
                    supported = Boolean.TRUE;
                } else if (bcInstalled && haveBc) {
                    providerClass = PROVIDER_CLASS;
                    providerName = BC_PROVIDER_NAME;
                    useName = true;
                    supported = Boolean.TRUE;
                } else if (haveFips) {
                    providerClass = FIPS_PROVIDER_CLASS;
                    providerName = BCFIPS_PROVIDER_NAME;
                    useName = false;
                    supported = Boolean.TRUE;
                } else if (haveBc) {
                    providerClass = PROVIDER_CLASS;
                    providerName = BC_PROVIDER_NAME;
                    supported = Boolean.TRUE;
                    useName = false;
                } else {
                    supported = Boolean.FALSE;
                }
            }
            supportHolder.set(supported);
        }

        return supported.booleanValue();
    }

    @Override
    protected Provider createProviderInstance(String providerClassName) throws ReflectiveOperationException {
        Provider result = BouncyCastleAccessor.INSTANCE.createProvider(providerClassName);
        if (result == null) {
            throw new ReflectiveOperationException("Cannot instantiate " + providerClassName);
        }
        return result;
    }

    @Override
    public PublicKey getPublicKey(PrivateKey key) {
        if (isEnabled() && isEdDSASupported() && key.getClass().getPackage().getName().startsWith("org.bouncycastle.")) {
            return BouncyCastlePublicKeyFactory.INSTANCE.getPublicKey(key);
        }
        return super.getPublicKey(key);
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
            edDSASupported = Boolean.valueOf(BouncyCastleEdDSAAccessor.INSTANCE.isSupported());
            edDSASupportHolder.set(edDSASupported);
            return edDSASupported;
        }
    }
}
