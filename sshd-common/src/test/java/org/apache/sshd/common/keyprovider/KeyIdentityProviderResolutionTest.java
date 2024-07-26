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

package org.apache.sshd.common.keyprovider;

import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class KeyIdentityProviderResolutionTest extends JUnitTestSupport {
    private KeyIdentityProvider p1;
    private KeyIdentityProvider p2;
    private KeyIdentityProvider expected;

    public void initKeyIdentityProviderResolutionTest(
            KeyIdentityProvider p1, KeyIdentityProvider p2, KeyIdentityProvider expected) {
        this.p1 = p1;
        this.p2 = p2;
        this.expected = expected;
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // Not serializing it
            private static final long serialVersionUID = 1L;

            {
                add(new Object[] { null, null, null });
                add(new Object[] { null, KeyIdentityProvider.EMPTY_KEYS_PROVIDER, KeyIdentityProvider.EMPTY_KEYS_PROVIDER });
                add(new Object[] { KeyIdentityProvider.EMPTY_KEYS_PROVIDER, null, KeyIdentityProvider.EMPTY_KEYS_PROVIDER });
                add(new Object[] {
                        KeyIdentityProvider.EMPTY_KEYS_PROVIDER, KeyIdentityProvider.EMPTY_KEYS_PROVIDER,
                        KeyIdentityProvider.EMPTY_KEYS_PROVIDER });

                KeyIdentityProvider p = createKeyIdentityProvider("MOCK");
                add(new Object[] { null, p, p });
                add(new Object[] { KeyIdentityProvider.EMPTY_KEYS_PROVIDER, p, p });
                add(new Object[] { p, null, p });
                add(new Object[] { p, KeyIdentityProvider.EMPTY_KEYS_PROVIDER, p });
            }

            private KeyIdentityProvider createKeyIdentityProvider(String name) {
                KeyIdentityProvider p = Mockito.mock(KeyIdentityProvider.class);
                Mockito.when(p.toString()).thenReturn(name);
                return p;
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "p1={0}, p2={1}, expected={2}")
    public void resolveKeyIdentityProvider(KeyIdentityProvider p1, KeyIdentityProvider p2, KeyIdentityProvider expected) {
        initKeyIdentityProviderResolutionTest(p1, p2, expected);
        assertSame(expected, KeyIdentityProvider.resolveKeyIdentityProvider(p1, p2));
    }
}
