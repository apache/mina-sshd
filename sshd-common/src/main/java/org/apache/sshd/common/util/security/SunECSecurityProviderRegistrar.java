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
 * This registrar is <em>enabled</em> by default. It can be disabled via a system property
 * {@code org.apache.sshd.security.provider.SunECWrapper.enabled=false}.
 * </p>
 * <p>
 * The registrar can be configured as usual. By default are enabled:
 * </p>
 * <dl>
 * <dt>"Ed25519"</dt>
 * <dd>{@code KeyFactory}, {@code KeyPairGenerator}, and {@code Signature}, if "Ed25519" is supported by SunEC</dd>
 * <dt>"X25519"</dt>
 * <dd>{@code KeyAgreement}, {@code KeyFactory}, and {@code KeyPairGenerator}, if "X25519" is supported by SunEC</dd>
 * <dt>"X448"</dt>
 * <dd>{@code KeyAgreement}, {@code KeyFactory}, and {@code KeyPairGenerator}, if "X448" is supported by SunEC</dd>
 * </dl>
 * <p>
 * Everything else is disabled.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SunECSecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {

    private static final String X25519 = "X25519";

    private static final String X448 = "X448";

    private final Map<String, String> defaultProperties = new HashMap<>();

    public SunECSecurityProviderRegistrar() {
        super("SunECWrapper");
        if (isSupported()) {
            Provider provider = getSecurityProvider();

            boolean haveEd25519 = have(SecurityUtils.ED25519, provider);
            boolean haveX25519 = have("X25519", provider);
            boolean haveX448 = have("X448", provider);

            String keyAgreement = null;
            String generator = null;
            String factory = null;
            String signature = null;
            if (haveEd25519) {
                generator = SecurityUtils.ED25519;
                factory = SecurityUtils.ED25519;
                signature = SecurityUtils.ED25519;
            }
            if (haveX25519) {
                keyAgreement = X25519;
                generator = generator == null ? X25519 : (generator + ',' + X25519);
                factory = factory == null ? X25519 : (factory + ',' + X25519);
            }
            if (haveX448) {
                keyAgreement = keyAgreement == null ? X448 : (keyAgreement + ',' + X448);
                generator = generator == null ? X448 : (generator + ',' + X448);
                factory = factory == null ? X448 : (factory + ',' + X448);
            }
            String baseName = getBasePropertyName();
            if (keyAgreement != null) {
                defaultProperties.put(baseName + ".KeyAgreement", keyAgreement);
            }
            if (generator != null) {
                defaultProperties.put(baseName + ".KeyPairGenerator", generator);
            }
            if (factory != null) {
                defaultProperties.put(baseName + ".KeyFactory", factory);
            }
            if (signature != null) {
                defaultProperties.put(baseName + ".Signature", signature);
            }
        }
    }

    private static boolean have(String algorithm, Provider provider) {
        try {
            KeyFactory factory = KeyFactory.getInstance(algorithm, provider);
            return factory != null;
        } catch (NoSuchAlgorithmException e) {
            return false;
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
