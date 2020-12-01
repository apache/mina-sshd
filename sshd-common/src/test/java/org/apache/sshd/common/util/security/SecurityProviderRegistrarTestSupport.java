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
import java.util.Arrays;
import java.util.Collection;

import org.apache.sshd.util.test.JUnitTestSupport;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class SecurityProviderRegistrarTestSupport extends JUnitTestSupport {
    protected SecurityProviderRegistrarTestSupport() {
        super();
    }

    public static Provider testGetSecurityProviderCaching(String prefix, SecurityProviderRegistrar registrar) {
        return testGetSecurityProviderCaching(prefix, registrar, registrar.getSecurityProvider());
    }

    public static <P extends Provider> P testGetSecurityProviderCaching(
            String prefix, SecurityProviderRegistrar registrar, P expected) {
        for (int index = 1; index <= Byte.SIZE; index++) {
            Provider actual = registrar.getSecurityProvider();
            assertSame(prefix + ": Mismatched provider instance at invocation #" + index, expected, actual);
        }

        return expected;
    }

    public static void assertSecurityEntitySupportState(
            String prefix, SecurityProviderRegistrar registrar, boolean expected, String name, Class<?>... entities) {
        assertSecurityEntitySupportState(prefix, registrar, expected, name, Arrays.asList(entities));
    }

    public static void assertSecurityEntitySupportState(
            String prefix, SecurityProviderRegistrar registrar, boolean expected, String name, Collection<Class<?>> entities) {
        for (Class<?> entity : entities) {
            assertEquals(prefix + "[" + entity.getSimpleName() + "]", expected,
                    registrar.isSecurityEntitySupported(entity, name));
        }
    }
}
