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

package org.apache.sshd.common.signature;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.signature.BuiltinSignatures.ParseResult;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class BuiltinSignaturesTest extends JUnitTestSupport {
    public BuiltinSignaturesTest() {
        super();
    }

    @Test
    void fromName() {
        for (BuiltinSignatures expected : BuiltinSignatures.VALUES) {
            String name = expected.getName();
            BuiltinSignatures actual = BuiltinSignatures.fromFactoryName(name);
            assertSame(expected, actual, name);
        }
    }

    @Test
    void parseSignaturesList() {
        List<String> builtin = NamedResource.getNameList(BuiltinSignatures.VALUES);
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
            ParseResult result = BuiltinSignatures.parseSignatureList(fullList);
            List<String> parsed = NamedResource.getNameList(result.getParsedFactories());
            List<String> missing = result.getUnsupportedFactories();

            // makes sure not only that the contents are the same but also the order
            assertListEquals(fullList + "[parsed]", builtin, parsed);
            assertListEquals(fullList + "[unsupported]", unknown, missing);
        }
    }

    @Test
    void resolveFactoryOnBuiltinValues() {
        for (SignatureFactory expected : BuiltinSignatures.VALUES) {
            String name = expected.getName();
            SignatureFactory actual = BuiltinSignatures.resolveFactory(name);
            assertSame(expected, actual, name);
        }
    }

    @Test
    void notAllowedToRegisterBuiltinFactories() {
        BuiltinSignatures.VALUES.forEach(expected -> assertThrows(IllegalArgumentException.class,
                () -> BuiltinSignatures.registerExtension(expected), "Unexpected success for " + expected.getName()));
    }

    @Test
    void notAllowedToOverrideRegisteredFactories() {
        assertThrows(IllegalArgumentException.class, () -> {
            SignatureFactory expected = Mockito.mock(SignatureFactory.class);
            Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

            String name = expected.getName();
            try {
                for (int index = 1; index <= Byte.SIZE; index++) {
                    BuiltinSignatures.registerExtension(expected);
                    assertEquals(1, index, "Unexpected success at attempt #" + index);
                }
            } finally {
                BuiltinSignatures.unregisterExtension(name);
            }
        });
    }

    @Test
    void resolveFactoryOnRegisteredExtension() {
        SignatureFactory expected = Mockito.mock(SignatureFactory.class);
        Mockito.when(expected.getName()).thenReturn(getCurrentTestName());

        String name = expected.getName();
        try {
            assertNull(BuiltinSignatures.resolveFactory(name), "Extension already registered");
            BuiltinSignatures.registerExtension(expected);

            SignatureFactory actual = BuiltinSignatures.resolveFactory(name);
            assertSame(expected, actual, "Mismatched resolved instance");
        } finally {
            SignatureFactory actual = BuiltinSignatures.unregisterExtension(name);
            assertSame(expected, actual, "Mismatched unregistered instance");
            assertNull(BuiltinSignatures.resolveFactory(name), "Extension not un-registered");
        }
    }
}
