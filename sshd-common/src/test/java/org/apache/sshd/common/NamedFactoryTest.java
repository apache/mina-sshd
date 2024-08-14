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
package org.apache.sshd.common;

import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("NoIoTestCase")
class NamedFactoryTest extends JUnitTestSupport {

    @Test
    void testBuiltinSupported() {
        List<Factory> input = new ArrayList<>();
        input.add(new Factory("A", false));
        input.add(new Factory("B", true));
        input.add(new Factory("C", false));
        input.add(new Factory("D", true));
        input.add(new Factory("E", false));
        List<Factory> filtered = NamedFactory.setUpBuiltinFactories(true, input);
        assertEquals(2, filtered.size());
        assertEquals("B", filtered.get(0).getName());
        assertEquals("D", filtered.get(1).getName());
    }

    @Test
    void testBuiltinUnsupported() {
        List<Factory> input = new ArrayList<>();
        input.add(new Factory("A", false));
        input.add(new Factory("B", true));
        input.add(new Factory("C", false));
        input.add(new Factory("D", true));
        input.add(new Factory("E", false));
        List<Factory> filtered = NamedFactory.setUpBuiltinFactories(false, input);
        assertIterableEquals(input, filtered);
    }

    @Test
    void testTransformedSupported() {
        List<OptionalFeature> input = new ArrayList<>();
        input.add(OptionalFeature.FALSE);
        input.add(OptionalFeature.TRUE);
        input.add(OptionalFeature.FALSE);
        input.add(OptionalFeature.TRUE);
        input.add(OptionalFeature.FALSE);
        List<Factory> filtered = NamedFactory.setUpTransformedFactories(true, input,
                o -> new Factory(o.toString(), o.isSupported()));
        assertEquals(2, filtered.size());
        assertTrue(filtered.stream().allMatch(Factory::isSupported));
    }

    @Test
    void testTransformedUnsupported() {
        List<OptionalFeature> input = new ArrayList<>();
        input.add(OptionalFeature.FALSE);
        input.add(OptionalFeature.TRUE);
        input.add(OptionalFeature.FALSE);
        input.add(OptionalFeature.TRUE);
        input.add(OptionalFeature.FALSE);
        List<Factory> filtered = NamedFactory.setUpTransformedFactories(false, input,
                o -> new Factory(o.toString(), o.isSupported()));
        assertEquals(input.size(), filtered.size());
        for (int i = 0; i < input.size(); i++) {
            assertEquals(input.get(i).isSupported(), filtered.get(i).isSupported());
        }
    }

    private static class Factory implements NamedResource, OptionalFeature {

        private final String name;

        private final boolean supported;

        Factory(String name, boolean supported) {
            this.name = name;
            this.supported = supported;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean isSupported() {
            return supported;
        }
    }
}
