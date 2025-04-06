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

package org.apache.sshd.common.config.keys;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collection;
import java.util.Collections;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.functors.UnaryEquator;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class BuiltinIdentitiesTest extends JUnitTestSupport {

    public static Collection<BuiltinIdentities> parameters() {
        return BuiltinIdentities.VALUES;
    }

    @BeforeAll // Dirty hack around the parameterized run
    static void testAllConstantsCovered() throws Exception {
        Field[] fields = BuiltinIdentities.Constants.class.getFields();
        for (Field f : fields) {
            int mods = f.getModifiers();
            if (!Modifier.isStatic(mods)) {
                continue;
            }

            if (!Modifier.isFinal(mods)) {
                continue;
            }

            Class<?> type = f.getType();
            if (!String.class.isAssignableFrom(type)) {
                continue;
            }

            String name = f.getName();
            String value = (String) f.get(null);
            BuiltinIdentities id = BuiltinIdentities.fromName(value);
            assertNotNull(id, "No match found for field " + name + "=" + value);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void fromName(BuiltinIdentities expected) {
        String name = expected.getName();
        for (int index = 0, count = name.length(); index < count; index++) {
            assertSame(expected, BuiltinIdentities.fromName(name), name);
            name = shuffleCase(name);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void fromAlgorithm(BuiltinIdentities expected) {
        String algorithm = expected.getAlgorithm();
        for (int index = 0, count = algorithm.length(); index < count; index++) {
            assertSame(expected, BuiltinIdentities.fromAlgorithm(algorithm), algorithm);
            algorithm = shuffleCase(algorithm);
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void fromKey(BuiltinIdentities expected) throws GeneralSecurityException {
        Assumptions.assumeTrue(expected.isSupported(), "Unsupported built-in identity");
        KeyPairGenerator gen = SecurityUtils.getKeyPairGenerator(expected.getAlgorithm());
        KeyPair kp = gen.generateKeyPair();
        outputDebugMessage("Checking built-in identity: %s", expected);
        assertSame(expected, BuiltinIdentities.fromKeyPair(kp), expected + "[pair]");
        assertSame(expected, BuiltinIdentities.fromKey(kp.getPublic()), expected + "[public]");
        assertSame(expected, BuiltinIdentities.fromKey(kp.getPrivate()), expected + "[private]");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void nonEmptySupportedKeyTypeNames(BuiltinIdentities expected) {
        assertTrue(GenericUtils.isNotEmpty(expected.getSupportedKeyTypes()));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    void noOverlappingKeyTypeNamesWithOtherIdentities(BuiltinIdentities expected) {
        Collection<String> current = expected.getSupportedKeyTypes();
        for (BuiltinIdentities identity : BuiltinIdentities.VALUES) {
            if (UnaryEquator.isSameReference(expected, identity)) {
                continue;
            }

            Collection<String> other = identity.getSupportedKeyTypes();
            if (!Collections.disjoint(current, other)) {
                fail("Overlapping key type names found for"
                     + " " + expected + " (" + current + ")"
                     + " and " + identity + " (" + other + ")");
            }
        }
    }
}
