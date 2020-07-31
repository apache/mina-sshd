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

package org.apache.sshd;

import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Makes sure default client/server setup satisfies various conditions
 *
 * @param  <M> The {@link AbstractFactoryManager} type being tested - can be client or server
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@Category({ NoIoTestCase.class })
public abstract class DefaultSetupTestSupport<M extends AbstractFactoryManager> extends BaseTestSupport {
    protected final M factory;

    protected DefaultSetupTestSupport(M factory) {
        this.factory = factory;
    }

    @Test
    public void testDefaultCiphersList() {
        assertNamedFactoriesList(Cipher.class.getSimpleName(), BaseBuilder.DEFAULT_CIPHERS_PREFERENCE,
                factory.getCipherFactories());
    }

    @Test   // SSHD-1004
    public void testNoDeprecatedCiphers() {
        assertNoDeprecatedSettings(Cipher.class.getSimpleName(),
                EnumSet.of(BuiltinCiphers.arcfour128, BuiltinCiphers.arcfour256, BuiltinCiphers.tripledescbc,
                        BuiltinCiphers.blowfishcbc),
                factory.getCipherFactories());
    }

    protected static <T, F extends NamedFactory<T>> void assertNoDeprecatedSettings(
            String hint, Collection<? extends F> unexpected, Collection<? extends F> actual) {
        Collection<String> disallowedNames = unexpected.stream()
                .map(NamedResource::getName)
                .collect(Collectors.toCollection(() -> new TreeSet<>(String.CASE_INSENSITIVE_ORDER)));
        for (F namedFactory : actual) {
            String name = namedFactory.getName();
            assertFalse(hint + " - disallowed: " + name, disallowedNames.contains(name));
        }
    }

    protected static <T, F extends NamedFactory<T>> void assertNamedFactoriesList(
            String hint, List<? extends F> expected, List<? extends F> actual) {
        int len = GenericUtils.size(expected);
        assertEquals(hint + "[size]", len, GenericUtils.size(actual));

        for (int index = 0; index < len; index++) {
            F expFactory = expected.get(index);
            F actFactory = actual.get(index);
            assertSame(hint + "[" + index + "]", expFactory, actFactory);
        }
    }
}
