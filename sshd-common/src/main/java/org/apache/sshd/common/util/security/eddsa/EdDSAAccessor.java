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

import java.security.Provider;

import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

final class EdDSAAccessor {

    static final EdDSAAccessor INSTANCE = new EdDSAAccessor();

    private EdDSAAccessor() {
        super();
    }

    public boolean isSupported() {
        try {
            // Just something that forces class loading.
            return Inner.isSupported();
        } catch (Throwable t) {
            return false;
        }
    }

    public Provider createProvider() {
        try {
            return Inner.createProvider();
        } catch (Throwable t) {
            return null;
        }
    }

    private static final class Inner {

        private Inner() {
            super();
        }

        static boolean isSupported() {
            return EdDSAKey.class != null;
        }

        static Provider createProvider() {
            return new EdDSASecurityProvider();
        }
    }
}
