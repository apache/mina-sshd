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

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.apache.sshd.common.util.security.SecurityProviderRegistrar;
import org.apache.sshd.common.util.security.SecurityProviderRegistrarTestSupport;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class EdDSASecurityProviderRegistrarTest extends SecurityProviderRegistrarTestSupport {
    private static SecurityProviderRegistrar registrarInstance;

    public EdDSASecurityProviderRegistrarTest() {
        super();
    }

    @BeforeClass
    public static void checkEDDSASupported() {
        Assume.assumeTrue(SecurityUtils.isEDDSACurveSupported());
        registrarInstance = new EdDSASecurityProviderRegistrar();
    }

    @Test
    public void testSupportedSecurityEntities() {
        assertSecurityEntitySupportState(getCurrentTestName(), registrarInstance, true, registrarInstance.getName(),
                KeyPairGenerator.class, KeyFactory.class);
        assertSecurityEntitySupportState(getCurrentTestName(), registrarInstance, true,
                SecurityUtils.CURVE_ED25519_SHA512, Signature.class);

        Collection<Class<?>> supported
                = new HashSet<>(Arrays.asList(KeyPairGenerator.class, KeyFactory.class, Signature.class));
        for (Class<?> entity : SecurityProviderRegistrar.SECURITY_ENTITIES) {
            if (supported.contains(entity)) {
                continue;
            }
            assertFalse("Unexpected support for " + entity.getSimpleName(),
                    registrarInstance.isSecurityEntitySupported(entity, registrarInstance.getName()));
        }
    }

    @Test
    public void testGetSecurityProvider() {
        Provider expected = registrarInstance.getSecurityProvider();
        assertNotNull("No provider created", expected);
        assertEquals("Mismatched provider name", registrarInstance.getName(), expected.getName());
        assertObjectInstanceOf("Mismatched provider type", EdDSASecurityProvider.class, expected);
    }

    @Test
    public void testGetSecurityProviderCaching() {
        testGetSecurityProviderCaching(getCurrentTestName(), registrarInstance);
    }
}
