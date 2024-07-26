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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class KexFactoryManagerTest extends BaseTestSupport {
    public KexFactoryManagerTest() {
        super();
    }

    @Test
    void defaultCompressionFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("", manager.getCompressionFactoriesNameList(), "Mismatched empty factories name list");

        String expected = NamedResource.getNames(BuiltinCompressions.VALUES);
        manager.setCompressionFactoriesNameList(expected);
        assertEquals(expected, manager.getCompressionFactoriesNameList(), "Mismatched updated factories name list");

        List<NamedFactory<Compression>> factories = manager.getCompressionFactories();
        assertEquals(BuiltinCompressions.VALUES.size(), GenericUtils.size(factories), "Mismatched updated factories count");

        for (NamedFactory<Compression> f : BuiltinCompressions.VALUES) {
            assertTrue(factories.contains(f), "Factory not set: " + f);
        }
    }

    @Test
    void defaultCipherFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("", manager.getCipherFactoriesNameList(), "Mismatched empty factories name list");

        String expected = NamedResource.getNames(BuiltinCiphers.VALUES);
        manager.setCipherFactoriesNameList(expected);
        assertEquals(expected, manager.getCipherFactoriesNameList(), "Mismatched updated factories name list");

        List<NamedFactory<Cipher>> factories = manager.getCipherFactories();
        assertEquals(BuiltinCiphers.VALUES.size(), GenericUtils.size(factories), "Mismatched updated factories count");

        for (NamedFactory<Cipher> f : BuiltinCiphers.VALUES) {
            assertTrue(factories.contains(f), "Factory not set: " + f);
        }
    }

    @Test
    void defaultMacFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("", manager.getMacFactoriesNameList(), "Mismatched empty factories name list");

        String expected = NamedResource.getNames(BuiltinMacs.VALUES);
        manager.setMacFactoriesNameList(expected);
        assertEquals(expected, manager.getMacFactoriesNameList(), "Mismatched updated factories name list");

        List<NamedFactory<Mac>> factories = manager.getMacFactories();
        assertEquals(BuiltinMacs.VALUES.size(), GenericUtils.size(factories), "Mismatched updated factories count");

        for (NamedFactory<Mac> f : BuiltinMacs.VALUES) {
            assertTrue(factories.contains(f), "Factory not set: " + f);
        }
    }

    @Test
    void defaultSignatureFactoriesMethods() {
        KexFactoryManager manager = new TestKexFactoryManager();
        assertEquals("", manager.getSignatureFactoriesNameList(), "Mismatched empty factories name list");

        String expected = NamedResource.getNames(BuiltinSignatures.VALUES);
        manager.setSignatureFactoriesNameList(expected);
        assertEquals(expected, manager.getSignatureFactoriesNameList(), "Mismatched updated factories name list");

        List<NamedFactory<Signature>> factories = manager.getSignatureFactories();
        assertEquals(BuiltinSignatures.VALUES.size(), GenericUtils.size(factories), "Mismatched updated factories count");

        for (NamedFactory<Signature> f : BuiltinSignatures.VALUES) {
            assertTrue(factories.contains(f), "Factory not set: " + f);
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
