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

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;

/**
 * This is registrar ensures that even if other registrars are active, we still use the Java built-in security provider
 * at least for some security entities.
 * <p>
 * The problem is that if the Bouncy Castle registrar is present and enabled, we'll end up using the Bouncy Castle
 * implementations for just about anything. But not all Bouncy Castle versions have native implementations of the
 * algorithms. If BC AES is used and is implemented in Java, performance will be very poor. SunJCE's AES uses native
 * code and is much faster.
 * </p>
 * <p>
 * If no Bouncy Castle is registered, this extra registrar will not have an effect. Like all registrars, this one can be
 * disabled via a system property {@code org.apache.sshd.security.provider.SunJCEWrapper.enabled=false}. Note that this
 * does <em>not</em> disable the fallback to the platform provider; it only disables this wrapper which can be used to
 * force the use of the "SunJCE" standard Java provider even if some other registrar also supports an algorithm (and
 * would thus normally be preferred).
 * </p>
 * <p>
 * The registrar can be configured as usual. By default it has only the AES cipher and the SHA macs enabled, everything
 * else is disabled.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SunJCESecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {

    private final Map<String, String> defaultProperties = new HashMap<>();

    public SunJCESecurityProviderRegistrar() {
        super("SunJCEWrapper");
        String baseName = getBasePropertyName();
        defaultProperties.put(baseName + ".Cipher", "AES");
        defaultProperties.put(baseName + ".Mac", "HmacSha1,HmacSha224,HmacSha256,HmacSha384,HmacSha512");
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
        return "SunJCE";
    }

    @Override
    public String getDefaultSecurityEntitySupportValue(Class<?> entityType) {
        return "";
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
