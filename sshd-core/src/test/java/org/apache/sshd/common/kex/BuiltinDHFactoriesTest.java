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

package org.apache.sshd.common.kex;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.kex.BuiltinDHFactories.ParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class BuiltinDHFactoriesTest extends BaseTestSupport {
    public BuiltinDHFactoriesTest() {
        super();
    }

    @Test
    public void testFromName() {
        for (BuiltinDHFactories expected : BuiltinDHFactories.VALUES) {
            String name = expected.getName();
            BuiltinDHFactories actual = BuiltinDHFactories.fromFactoryName(name);
            assertSame(name, expected, actual);
        }
    }

    @Test
    public void testAllConstantsCovered() throws Exception {
        Set<BuiltinDHFactories> avail = EnumSet.noneOf(BuiltinDHFactories.class);
        Field[] fields = BuiltinDHFactories.Constants.class.getFields();
        for (Field f : fields) {
            String name = (String) f.get(null);
            BuiltinDHFactories value = BuiltinDHFactories.fromFactoryName(name);
            assertNotNull("No match found for " + name, value);
            assertTrue(name + " re-specified", avail.add(value));
        }

        assertEquals("Incomplete coverage", BuiltinDHFactories.VALUES, avail);
    }

    @Test
    public void testParseDHFactorysList() {
        List<String> builtin = NamedResource.getNameList(BuiltinDHFactories.VALUES);
        List<String> unknown
                = Arrays.asList(getClass().getPackage().getName(), getClass().getSimpleName(), getCurrentTestName());
        Random rnd = new Random();
        for (int index = 0; index < (builtin.size() + unknown.size()); index++) {
            Collections.shuffle(builtin, rnd);
            Collections.shuffle(unknown, rnd);

            List<String> weavedList = new ArrayList<>(builtin.size() + unknown.size());
            for (int bIndex = 0, uIndex = 0; (bIndex < builtin.size()) || (uIndex < unknown.size());) {
                boolean useBuiltin = false;
                if (bIndex < builtin.size()) {
                    useBuiltin = uIndex >= unknown.size() || rnd.nextBoolean();
                }

                if (useBuiltin) {
                    weavedList.add(builtin.get(bIndex));
                    bIndex++;
                } else if (uIndex < unknown.size()) {
                    weavedList.add(unknown.get(uIndex));
                    uIndex++;
                }
            }

            String fullList = GenericUtils.join(weavedList, ',');
            ParseResult result = BuiltinDHFactories.parseDHFactoriesList(fullList);
            List<String> parsed = NamedResource.getNameList(result.getParsedFactories());
            List<String> missing = result.getUnsupportedFactories();

            // makes sure not only that the contents are the same but also the order
            assertListEquals(fullList + "[parsed]", builtin, parsed);
            assertListEquals(fullList + "[unsupported]", unknown, missing);
        }
    }

    @Test
    public void testResolveFactoryOnBuiltinValues() {
        for (DHFactory expected : BuiltinDHFactories.VALUES) {
            String name = expected.getName();
            DHFactory actual = BuiltinDHFactories.resolveFactory(name);
            assertSame(name, expected, actual);
        }
    }

    @Test
    public void testNotAllowedToRegisterBuiltinFactories() {
        for (DHFactory expected : BuiltinDHFactories.VALUES) {
            try {
                BuiltinDHFactories.registerExtension(expected);
                fail("Unexpected success for " + expected.getName());
            } catch (IllegalArgumentException e) {
                // expected - ignored
            }
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNotAllowedToOverrideRegisteredFactories() {
        DHFactory expected = Mockito.mock(DHFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String name = expected.getName();
        try {
            for (int index = 1; index <= Byte.SIZE; index++) {
                BuiltinDHFactories.registerExtension(expected);
                assertEquals("Unexpected success at attempt #" + index, 1, index);
            }
        } finally {
            BuiltinDHFactories.unregisterExtension(name);
        }
    }

    @Test
    public void testResolveFactoryOnRegisteredExtension() {
        DHFactory expected = Mockito.mock(DHFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String name = expected.getName();
        try {
            assertNull("Extension already registered", BuiltinDHFactories.resolveFactory(name));
            BuiltinDHFactories.registerExtension(expected);

            DHFactory actual = BuiltinDHFactories.resolveFactory(name);
            assertSame("Mismatched resolved instance", expected, actual);
        } finally {
            DHFactory actual = BuiltinDHFactories.unregisterExtension(name);
            assertSame("Mismatched unregistered instance", expected, actual);
            assertNull("Extension not un-registered", BuiltinDHFactories.resolveFactory(name));
        }
    }

    @Test
    public void testDHG() throws Exception {
        for (DHFactory expected : BuiltinDHFactories.VALUES) {
            if (!expected.isGroupExchange()) {
                if (expected.isSupported()) {
                    assertNotNull(expected + ": Null DH created", expected.create());
                }
            }
        }
    }

    @Test
    public void testDHGRead() throws Exception {
        assertArrayEquals("P1", DHGroupData.getP1(), DHGroupData.getOakleyGroupPrimeValue("group2.prime"));
        assertArrayEquals("P14", DHGroupData.getP14(), DHGroupData.getOakleyGroupPrimeValue("group14.prime"));
    }
}
