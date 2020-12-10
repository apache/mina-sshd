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
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KeyExchange;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
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
        assertSameNamedFactoriesListInstances(Cipher.class.getSimpleName(), BaseBuilder.DEFAULT_CIPHERS_PREFERENCE,
                factory.getCipherFactories());
    }

    @Test   // SSHD-1004
    @SuppressWarnings("deprecation")
    public void testNoDeprecatedCiphers() {
        assertNoDeprecatedFactoryInstanceNames(Cipher.class.getSimpleName(),
                EnumSet.of(BuiltinCiphers.arcfour128, BuiltinCiphers.arcfour256, BuiltinCiphers.tripledescbc,
                        BuiltinCiphers.blowfishcbc),
                factory.getCipherFactories());
    }

    @Test
    public void testDefaultKeyExchangeList() {
        assertSameNamedResourceListNames(KeyExchange.class.getSimpleName(),
                BaseBuilder.DEFAULT_KEX_PREFERENCE, factory.getKeyExchangeFactories());
    }

    @Test   // SSHD-1004
    public void testNoDeprecatedKeyExchanges() {
        Collection<? extends NamedResource> disallowed = BuiltinDHFactories.VALUES.stream()
                .filter(f -> f.getName().endsWith("sha-1"))
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(BuiltinDHFactories.class)));
        assertNoDeprecatedFactoryInstanceNames(
                KeyExchange.class.getSimpleName(), disallowed, factory.getKeyExchangeFactories());
    }

    @Test
    public void testDefaultSignaturesList() {
        assertSameNamedFactoriesListInstances(
                Signature.class.getSimpleName(), BaseBuilder.DEFAULT_SIGNATURE_PREFERENCE, factory.getSignatureFactories());
    }

    @Test   // SSHD-1004
    @SuppressWarnings("deprecation")
    public void testNoDeprecatedSignatures() {
        assertNoDeprecatedFactoryInstanceNames(Cipher.class.getSimpleName(),
                EnumSet.of(BuiltinSignatures.dsa, BuiltinSignatures.rsa_cert, BuiltinSignatures.dsa_cert),
                factory.getSignatureFactories());

    }

    @Test
    public void testDefaultMacsList() {
        assertSameNamedFactoriesListInstances(
                Mac.class.getSimpleName(), BaseBuilder.DEFAULT_MAC_PREFERENCE, factory.getMacFactories());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testNoDeprecatedMacs() {
        assertNoDeprecatedFactoryInstanceNames(
                Mac.class.getSimpleName(), EnumSet.of(BuiltinMacs.hmacmd5, BuiltinMacs.hmacmd596, BuiltinMacs.hmacsha196),
                factory.getMacFactories());
    }

    protected static void assertSameNamedResourceListNames(
            String hint, List<? extends NamedResource> expected, List<? extends NamedResource> actual) {
        int len = GenericUtils.size(expected);
        assertEquals(hint + "[size]", len, GenericUtils.size(actual));

        for (int index = 0; index < len; index++) {
            NamedResource expRes = expected.get(index);
            String expName = expRes.getName();
            NamedResource actRes = actual.get(index);
            String actName = actRes.getName();
            assertSame(hint + "[" + index + "]", expName, actName);
        }
    }

    protected static void assertNoDeprecatedFactoryInstanceNames(
            String hint, Collection<? extends NamedResource> unexpected, Collection<? extends NamedResource> actual) {
        Collection<String> disallowedNames = unexpected.stream()
                .map(NamedResource::getName)
                .collect(Collectors.toCollection(() -> new TreeSet<>(String.CASE_INSENSITIVE_ORDER)));
        for (NamedResource namedFactory : actual) {
            String name = namedFactory.getName();
            assertFalse(hint + " - disallowed: " + name, disallowedNames.contains(name));
        }
    }

    protected static <T, F extends NamedFactory<T>> void assertSameNamedFactoriesListInstances(
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
