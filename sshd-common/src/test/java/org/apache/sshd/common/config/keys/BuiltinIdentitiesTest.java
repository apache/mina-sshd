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
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class BuiltinIdentitiesTest extends JUnitTestSupport {
    private final BuiltinIdentities expected;

    public BuiltinIdentitiesTest(BuiltinIdentities expected) {
        this.expected = expected;
    }

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return parameterize(BuiltinIdentities.VALUES);
    }

    @BeforeClass // Dirty hack around the parameterized run
    public static void testAllConstantsCovered() throws Exception {
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
            assertNotNull("No match found for field " + name + "=" + value, id);
        }
    }

    @Test
    public void testFromName() {
        String name = expected.getName();
        for (int index = 0, count = name.length(); index < count; index++) {
            assertSame(name, expected, BuiltinIdentities.fromName(name));
            name = shuffleCase(name);
        }
    }

    @Test
    public void testFromAlgorithm() {
        String algorithm = expected.getAlgorithm();
        for (int index = 0, count = algorithm.length(); index < count; index++) {
            assertSame(algorithm, expected, BuiltinIdentities.fromAlgorithm(algorithm));
            algorithm = shuffleCase(algorithm);
        }
    }

    @Test
    public void testFromKey() throws GeneralSecurityException {
        Assume.assumeTrue("Unsupported built-in identity", expected.isSupported());
        KeyPairGenerator gen = SecurityUtils.getKeyPairGenerator(expected.getAlgorithm());
        KeyPair kp = gen.generateKeyPair();
        outputDebugMessage("Checking built-in identity: %s", expected);
        assertSame(expected + "[pair]", expected, BuiltinIdentities.fromKeyPair(kp));
        assertSame(expected + "[public]", expected, BuiltinIdentities.fromKey(kp.getPublic()));
        assertSame(expected + "[private]", expected, BuiltinIdentities.fromKey(kp.getPrivate()));
    }

    @Test
    public void testNonEmptySupportedKeyTypeNames() {
        assertTrue(GenericUtils.isNotEmpty(expected.getSupportedKeyTypes()));
    }

    @Test
    public void testNoOverlappingKeyTypeNamesWithOtherIdentities() {
        Collection<String> current = expected.getSupportedKeyTypes();
        for (BuiltinIdentities identity : BuiltinIdentities.VALUES) {
            if (GenericUtils.isSameReference(expected, identity)) {
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

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + expected + "]";
    }
}
