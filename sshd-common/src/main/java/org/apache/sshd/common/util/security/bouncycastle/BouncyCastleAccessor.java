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

import java.security.Provider;

import org.apache.sshd.common.util.ReflectionUtils;

final class BouncyCastleAccessor {

    static final BouncyCastleAccessor INSTANCE = new BouncyCastleAccessor();

    private BouncyCastleAccessor() {
        super();
    }

    public Class<?> getProviderClass(String className) {
        try {
            if (BouncyCastleSecurityProviderRegistrar.FIPS_PROVIDER_CLASS.equals(className)) {
                return Class.forName(className);
            } else if (BouncyCastleSecurityProviderRegistrar.PROVIDER_CLASS.equals(className)) {
                return Inner.getProviderClass();
            }
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    public Provider createProvider(String className) throws ReflectiveOperationException {
        try {
            if (BouncyCastleSecurityProviderRegistrar.FIPS_PROVIDER_CLASS.equals(className)) {
                try {
                    return ReflectionUtils.newInstance(Class.forName(className), Provider.class);
                } catch (ClassNotFoundException e) {
                    return null;
                }
            } else if (BouncyCastleSecurityProviderRegistrar.PROVIDER_CLASS.equals(className)) {
                return Inner.createProvider();
            }
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static final class Inner {

        private Inner() {
            super();
        }

        static Class<?> getProviderClass() {
            try {
                return org.bouncycastle.jce.provider.BouncyCastleProvider.class;
            } catch (Throwable t) {
                return null;
            }
        }

        static Provider createProvider() {
            try {
                return new org.bouncycastle.jce.provider.BouncyCastleProvider();
            } catch (Throwable t) {
                return null;
            }
        }
    }

}
