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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class EdDSASecurityProviderRegistrarTest extends SecurityProviderRegistrarTestSupport {
    private static SecurityProviderRegistrar registrarInstance;

    public EdDSASecurityProviderRegistrarTest() {
        super();
    }

    @BeforeAll
    static void checkEDDSASupported() {
        Assumptions.assumeTrue(SecurityUtils.isEDDSACurveSupported());
        registrarInstance = new EdDSASecurityProviderRegistrar();
    }

    @Test
    void supportedSecurityEntities() {
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
            assertFalse(registrarInstance.isSecurityEntitySupported(entity, registrarInstance.getName()),
                    "Unexpected support for " + entity.getSimpleName());
        }
    }

    @Test
    void getSecurityProvider() {
        Provider expected = registrarInstance.getSecurityProvider();
        assertNotNull(expected, "No provider created");
        assertEquals(registrarInstance.getName(), expected.getName(), "Mismatched provider name");
        assertObjectInstanceOf("Mismatched provider type", EdDSASecurityProvider.class, expected);
    }

    @Test
    void getSecurityProviderCaching() {
        testGetSecurityProviderCaching(getCurrentTestName(), registrarInstance);
    }
}
