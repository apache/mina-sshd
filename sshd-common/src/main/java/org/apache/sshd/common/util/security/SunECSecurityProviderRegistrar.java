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
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;

/**
 * This is registrar ensures that even if other registrars are active, we still use the Java built-in security provider
 * at least for some security entities.
 * <p>
 * This registrar can be used to enforce using some security entities from the JDK's SunEC provider even if other
 * registrars also provide the same entity. Care should be taken to use consistent configurations. For instance, to use
 * EC keys from this provider instead of Bouncy Castle, all of "KeyPairGenerator", "KeyFactory", and "Signature" should
 * be set correctly. Mixing SunEC keys with Bouncy Castle signatures won't work.
 * </p>
 * <p>
 * This registrar is <em>disabled</em> by default. It can be enabled via a system property
 * {@code org.apache.sshd.security.provider.SunECWrapper.enabled=true}.
 * </p>
 * <p>
 * The registrar can be configured as usual. By default it has only the "Ed25519" {@code KeyFactory},
 * {@code KeyPairGenerator}, and {@code Signature} enabled; everything else is disabled.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SunECSecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {

    private final Map<String, String> defaultProperties = new HashMap<>();

    public SunECSecurityProviderRegistrar() {
        super("SunECWrapper");
        String baseName = getBasePropertyName();
        defaultProperties.put(baseName + ".enabled", "false");
        if (isSupported()) {
            boolean haveEd25519;
            try {
                KeyFactory factory = KeyFactory.getInstance(SecurityUtils.ED25519, getSecurityProvider());
                haveEd25519 = factory != null;
            } catch (NoSuchAlgorithmException e) {
                haveEd25519 = false;
            }
            if (haveEd25519) {
                defaultProperties.put(baseName + ".KeyPairGenerator", "Ed25519");
                defaultProperties.put(baseName + ".KeyFactory", "Ed25519");
                defaultProperties.put(baseName + ".Signature", "Ed25519");
            }
        }
    }

    @Override
    public boolean isEnabled() {
        if (SecurityUtils.isFipsMode() || !super.isEnabled()) {
            return false;
        }
        return isSupported();
    }

    @Override
    public String getProviderName() {
        return "SunEC";
    }

    @Override
    public String getDefaultSecurityEntitySupportValue(Class<?> entityType) {
        return "";
    }

    @Override
    public Boolean getBoolean(String name) {
        Boolean configured = super.getBoolean(name);
        if (configured == null) {
            String value = defaultProperties.get(name);
            if (value != null) {
                configured = Boolean.valueOf(value);
            }
        }
        return configured;
    }

    @Override
    public boolean getBooleanProperty(String name, boolean def) {
        Boolean configured = getBoolean(name);
        if (configured == null) {
            return def;
        }
        return configured.booleanValue();
    }

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

    @Override
    public boolean isNamedProviderUsed() {
        return false;
    }

    @Override
    public Provider getSecurityProvider() {
        return Security.getProvider(getProviderName());
    }

    @Override
    public boolean isSupported() {
        return getSecurityProvider() != null;
    }

}
