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
package org.apache.sshd.common.util.security.androidopenssl;

import java.security.Provider;
import java.security.Security;

import org.apache.sshd.common.util.security.AbstractSecurityProviderRegistrar;

public class AndroidOpenSSLSecurityProviderRegistrar extends AbstractSecurityProviderRegistrar {
    public AndroidOpenSSLSecurityProviderRegistrar() {
        super("AndroidOpenSSL");
    }

    @Override
    public boolean isSupported() {
        // Check that we are running on Android
        // https://developer.android.com/reference/java/lang/System#getProperties()
        return "The Android Project".equals(System.getProperty("java.specification.vendor"));
    }

    @Override
    public String getDefaultSecurityEntitySupportValue(Class<?> entityType) {
        return ALL_OPTIONS_VALUE;
    }

    @Override
    public Provider getSecurityProvider() {
        return Security.getProvider("AndroidOpenSSL");
    }
}
