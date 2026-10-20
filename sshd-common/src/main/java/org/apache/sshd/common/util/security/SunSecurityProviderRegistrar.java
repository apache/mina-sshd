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
package org.apache.sshd.common.util.security;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import org.apache.sshd.common.util.GenericUtils;

/**
 * Prefers the JDK SUN provider for ML-DSA key factories and key pair generators. The
 * {@code org.apache.sshd.security.provider.SunWrapper.enabled=false} property disables this registrar.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SunSecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {

    private final Map<String, String> defaultProperties = new HashMap<>();

    /**
     * Creates a registrar with the ML-DSA key services available from SUN.
     */
    public SunSecurityProviderRegistrar() {
        super("SunWrapper");
        if (isSupported()) {
            Provider provider = getSecurityProvider();
            StringJoiner factories = new StringJoiner(",");
            StringJoiner generators = new StringJoiner(",");
            for (MLDSAParameterSets variant : MLDSAParameterSets.values()) {
                String algorithm = variant.getJceName();
                try {
                    KeyFactory.getInstance(algorithm, provider);
                    factories.add(algorithm);
                } catch (NoSuchAlgorithmException e) {
                    // This parameter set is unavailable on this JDK.
                }
                try {
                    KeyPairGenerator.getInstance(algorithm, provider);
                    generators.add(algorithm);
                } catch (NoSuchAlgorithmException e) {
                    // This parameter set is unavailable on this JDK.
                }
            }
            String baseName = getBasePropertyName();
            defaultProperties.put(baseName + ".KeyFactory", factories.toString());
            defaultProperties.put(baseName + ".KeyPairGenerator", generators.toString());
        }
    }

    /**
     * @return whether the registrar is enabled and SUN is available
     */
    @Override
    public boolean isEnabled() {
        if (SecurityUtils.isFipsMode() || !super.isEnabled()) {
            return false;
        }
        return isSupported();
    }

    /**
     * @return the SUN provider name
     */
    @Override
    public String getProviderName() {
        return "SUN";
    }

    /**
     * @param  entityType the security entity type
     * @return            an empty default support list
     */
    @Override
    public String getDefaultSecurityEntitySupportValue(Class<?> entityType) {
        return "";
    }

    /**
     * @param  name the property name
     * @return      the configured value, or the default for available ML-DSA key services
     */
    @Override
    public String getString(String name) {
        String configured = super.getString(name);
        if (GenericUtils.isEmpty(configured)) {
            String byDefault = defaultProperties.get(name);
            if (byDefault != null) {
                return byDefault;
            }
        }
        return configured;
    }

    /**
     * @return {@code false}; this registrar uses the provider instance
     */
    @Override
    public boolean isNamedProviderUsed() {
        return false;
    }

    /**
     * @return the installed SUN provider, or {@code null} if unavailable
     */
    @Override
    public Provider getSecurityProvider() {
        return Security.getProvider(getProviderName());
    }

    /**
     * @return whether SUN is installed
     */
    @Override
    public boolean isSupported() {
        return getSecurityProvider() != null;
    }
}
