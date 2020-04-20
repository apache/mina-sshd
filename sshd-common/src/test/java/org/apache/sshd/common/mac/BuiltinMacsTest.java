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

package org.apache.sshd.common.mac;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.mac.BuiltinMacs.ParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
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
public class BuiltinMacsTest extends JUnitTestSupport {
    public BuiltinMacsTest() {
        super();
    }

    @Test
    public void testFromName() {
        for (BuiltinMacs expected : BuiltinMacs.VALUES) {
            String name = expected.getName();
            BuiltinMacs actual = BuiltinMacs.fromFactoryName(name);
            assertSame(name, expected, actual);
        }
    }

    @Test
    public void testAllConstantsCovered() throws Exception {
        Set<BuiltinMacs> avail = EnumSet.noneOf(BuiltinMacs.class);
        Field[] fields = BuiltinMacs.Constants.class.getFields();
        for (Field f : fields) {
            String name = (String) f.get(null);
            BuiltinMacs value = BuiltinMacs.fromFactoryName(name);
            assertNotNull("No match found for " + name, value);
            assertTrue(name + " re-specified", avail.add(value));
        }

        assertEquals("Incomplete coverage", BuiltinMacs.VALUES, avail);
    }

    @Test
    public void testParseMacsList() {
        List<String> builtin = NamedResource.getNameList(BuiltinMacs.VALUES);
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
            ParseResult result = BuiltinMacs.parseMacsList(fullList);
            List<String> parsed = NamedResource.getNameList(result.getParsedFactories());
            List<String> missing = result.getUnsupportedFactories();

            // makes sure not only that the contents are the same but also the order
            assertListEquals(fullList + "[parsed]", builtin, parsed);
            assertListEquals(fullList + "[unsupported]", unknown, missing);
        }
    }

    @Test
    public void testResolveFactoryOnBuiltinValues() {
        for (MacFactory expected : BuiltinMacs.VALUES) {
            String name = expected.getName();
            MacFactory actual = BuiltinMacs.resolveFactory(name);
            assertSame(name, expected, actual);
        }
    }

    @Test
    public void testNotAllowedToRegisterBuiltinFactories() {
        for (MacFactory expected : BuiltinMacs.VALUES) {
            try {
                BuiltinMacs.registerExtension(expected);
                fail("Unexpected success for " + expected.getName());
            } catch (IllegalArgumentException e) {
                // expected - ignored
            }
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNotAllowedToOverrideRegisteredFactories() {
        MacFactory expected = Mockito.mock(MacFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String name = expected.getName();
        try {
            for (int index = 1; index <= Byte.SIZE; index++) {
                BuiltinMacs.registerExtension(expected);
                assertEquals("Unexpected success at attempt #" + index, 1, index);
            }
        } finally {
            BuiltinMacs.unregisterExtension(name);
        }
    }

    @Test
    public void testResolveFactoryOnRegisteredExtension() {
        MacFactory expected = Mockito.mock(MacFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String name = expected.getName();
        try {
            assertNull("Extension already registered", BuiltinMacs.resolveFactory(name));
            BuiltinMacs.registerExtension(expected);

            MacFactory actual = BuiltinMacs.resolveFactory(name);
            assertSame("Mismatched resolved instance", expected, actual);
        } finally {
            MacFactory actual = BuiltinMacs.unregisterExtension(name);
            assertSame("Mismatched unregistered instance", expected, actual);
            assertNull("Extension not un-registered", BuiltinMacs.resolveFactory(name));
        }
    }
}
