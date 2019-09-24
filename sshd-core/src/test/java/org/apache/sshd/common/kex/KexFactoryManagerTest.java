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

import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.kex.extension.KexExtensionHandler;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class KexFactoryManagerTest extends BaseTestSupport {
    public KexFactoryManagerTest() {
        super();
    }

    @Test
    public void testDefaultCompressionFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("Mismatched empty factories name list", "", manager.getCompressionFactoriesNameList());

        String expected = NamedResource.getNames(BuiltinCompressions.VALUES);
        manager.setCompressionFactoriesNameList(expected);
        assertEquals("Mismatched updated factories name list", expected, manager.getCompressionFactoriesNameList());

        List<NamedFactory<Compression>> factories = manager.getCompressionFactories();
        assertEquals("Mismatched updated factories count", BuiltinCompressions.VALUES.size(), GenericUtils.size(factories));

        for (NamedFactory<Compression> f : BuiltinCompressions.VALUES) {
            assertTrue("Factory not set: " + f, factories.contains(f));
        }
    }

    @Test
    public void testDefaultCipherFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("Mismatched empty factories name list", "", manager.getCipherFactoriesNameList());

        String expected = NamedResource.getNames(BuiltinCiphers.VALUES);
        manager.setCipherFactoriesNameList(expected);
        assertEquals("Mismatched updated factories name list", expected, manager.getCipherFactoriesNameList());

        List<NamedFactory<Cipher>> factories = manager.getCipherFactories();
        assertEquals("Mismatched updated factories count", BuiltinCiphers.VALUES.size(), GenericUtils.size(factories));

        for (NamedFactory<Cipher> f : BuiltinCiphers.VALUES) {
            assertTrue("Factory not set: " + f, factories.contains(f));
        }
    }

    @Test
    public void testDefaultMacFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("Mismatched empty factories name list", "", manager.getMacFactoriesNameList());

        String expected = NamedResource.getNames(BuiltinMacs.VALUES);
        manager.setMacFactoriesNameList(expected);
        assertEquals("Mismatched updated factories name list", expected, manager.getMacFactoriesNameList());

        List<NamedFactory<Mac>> factories = manager.getMacFactories();
        assertEquals("Mismatched updated factories count", BuiltinMacs.VALUES.size(), GenericUtils.size(factories));

        for (NamedFactory<Mac> f : BuiltinMacs.VALUES) {
            assertTrue("Factory not set: " + f, factories.contains(f));
        }
    }

    @Test
    public void testDefaultSignatureFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("Mismatched empty factories name list", "", manager.getSignatureFactoriesNameList());

        String expected = NamedResource.getNames(BuiltinSignatures.VALUES);
        manager.setSignatureFactoriesNameList(expected);
        assertEquals("Mismatched updated factories name list", expected, manager.getSignatureFactoriesNameList());

        List<NamedFactory<Signature>> factories = manager.getSignatureFactories();
        assertEquals("Mismatched updated factories count", BuiltinSignatures.VALUES.size(), GenericUtils.size(factories));

        for (NamedFactory<Signature> f : BuiltinSignatures.VALUES) {
            assertTrue("Factory not set: " + f, factories.contains(f));
        }
    }

    static class TestKexFactoryManager implements KexFactoryManager {
        private List<NamedFactory<Compression>> compressions;
        private List<NamedFactory<Cipher>> ciphers;
        private List<NamedFactory<Mac>> macs;
        private List<NamedFactory<Signature>> signatures;
        private KexExtensionHandler kexExtensionHandler;

        TestKexFactoryManager() {
            super();
        }

        @Override
        public List<NamedFactory<Signature>> getSignatureFactories() {
            return signatures;
        }

        @Override
        public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
            signatures = factories;
        }

        @Override
        public List<KeyExchangeFactory> getKeyExchangeFactories() {
            return null;
        }

        @Override
        public void setKeyExchangeFactories(List<KeyExchangeFactory> keyExchangeFactories) {
            throw new UnsupportedOperationException("N/A");
        }

        @Override
        public List<NamedFactory<Cipher>> getCipherFactories() {
            return ciphers;
        }

        @Override
        public void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories) {
            ciphers = cipherFactories;
        }

        @Override
        public List<NamedFactory<Compression>> getCompressionFactories() {
            return compressions;
        }

        @Override
        public void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories) {
            compressions = compressionFactories;
        }

        @Override
        public List<NamedFactory<Mac>> getMacFactories() {
            return macs;
        }

        @Override
        public void setMacFactories(List<NamedFactory<Mac>> macFactories) {
            macs = macFactories;
        }

        @Override
        public KexExtensionHandler getKexExtensionHandler() {
            return kexExtensionHandler;
        }

        @Override
        public void setKexExtensionHandler(KexExtensionHandler handler) {
            this.kexExtensionHandler = handler;
        }
    }
}
