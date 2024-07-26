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

package org.apache.sshd.common.config;

import java.io.IOException;
import java.io.Reader;
import java.io.StreamCorruptedException;
import java.io.StringReader;
import java.net.URL;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.function.Function;

import org.apache.sshd.common.BaseBuilder;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.compression.CompressionFactory;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.kex.BuiltinDHFactories;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
@SuppressWarnings("checkstyle:MethodCount")
public class SshConfigFileReaderTest extends BaseTestSupport {
    public SshConfigFileReaderTest() {
        super();
    }

    @Test
    void readFromURL() throws IOException {
        URL url = getClass().getResource("sshd_config");
        assertNotNull(url, "Cannot locate test file");

        Properties props = ConfigFileReaderSupport.readConfigFile(url);
        assertFalse(props.isEmpty(), "No properties read");
        assertTrue(GenericUtils.isEmpty(props.getProperty("ListenAddress")), "Unexpected commented property data");
        assertTrue(GenericUtils.isEmpty(props.getProperty(getCurrentTestName())), "Unexpected non-existing property data");

        String keysList = props.getProperty("HostKey");
        assertFalse(GenericUtils.isEmpty(keysList), "No host keys");

        String[] keys = GenericUtils.split(keysList, ',');
        assertTrue(GenericUtils.length((Object[]) keys) > 1, "No multiple keys");
    }

    @Test
    void parseCiphersList() {
        List<? extends NamedResource> expected = BaseBuilder.DEFAULT_CIPHERS_PREFERENCE;
        Properties props = initNamedResourceProperties(ConfigFileReaderSupport.CIPHERS_CONFIG_PROP, expected);
        BuiltinCiphers.ParseResult result = SshConfigFileReader.getCiphers(PropertyResolverUtils.toPropertyResolver(props));
        testParsedFactoriesList(expected, result.getParsedFactories(), result.getUnsupportedFactories());
    }

    @Test
    void parseMacsList() {
        List<? extends NamedResource> expected = BaseBuilder.DEFAULT_MAC_PREFERENCE;
        Properties props = initNamedResourceProperties(ConfigFileReaderSupport.MACS_CONFIG_PROP, expected);
        BuiltinMacs.ParseResult result = SshConfigFileReader.getMacs(PropertyResolverUtils.toPropertyResolver(props));
        testParsedFactoriesList(expected, result.getParsedFactories(), result.getUnsupportedFactories());
    }

    @Test
    void parseSignaturesList() {
        List<? extends NamedResource> expected = BaseBuilder.DEFAULT_SIGNATURE_PREFERENCE;
        Properties props = initNamedResourceProperties(ConfigFileReaderSupport.HOST_KEY_ALGORITHMS_CONFIG_PROP, expected);
        BuiltinSignatures.ParseResult result
                = SshConfigFileReader.getSignatures(PropertyResolverUtils.toPropertyResolver(props));
        testParsedFactoriesList(expected, result.getParsedFactories(), result.getUnsupportedFactories());
    }

    @Test
    void parseKexFactoriesList() {
        List<? extends NamedResource> expected = BaseBuilder.DEFAULT_KEX_PREFERENCE;
        Properties props = initNamedResourceProperties(ConfigFileReaderSupport.KEX_ALGORITHMS_CONFIG_PROP, expected);
        BuiltinDHFactories.ParseResult result
                = SshConfigFileReader.getKexFactories(PropertyResolverUtils.toPropertyResolver(props));
        testParsedFactoriesList(expected, result.getParsedFactories(), result.getUnsupportedFactories());
    }

    @Test
    void getCompression() {
        Properties props = new Properties();
        for (CompressionConfigValue expected : CompressionConfigValue.VALUES) {
            props.setProperty(ConfigFileReaderSupport.COMPRESSION_PROP, expected.name().toLowerCase());

            NamedResource actual = SshConfigFileReader.getCompression(PropertyResolverUtils.toPropertyResolver(props));
            assertNotNull(actual, "No match for " + expected.name());
            assertEquals(expected.getName(), actual.getName(), expected.name());
        }
    }

    @Test
    void configureAbstractFactoryManagerWithDefaults() {
        Properties props = new Properties(); // empty means use defaults
        AbstractFactoryManager expected = new AbstractFactoryManager() {
            @Override
            protected Closeable getInnerCloseable() {
                return null;
            }
        };
        // must be lenient since we do not cover the full default spectrum
        AbstractFactoryManager actual = SshConfigFileReader.configure(
                expected, PropertyResolverUtils.toPropertyResolver(props), true, true);
        assertSame(expected, actual, "Mismatched configured result");
        validateAbstractFactoryManagerConfiguration(expected, props, true);
    }

    @Test
    void nonLenientCiphersConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> {
            FactoryManager manager = SshConfigFileReader.configureCiphers(
                    new AbstractFactoryManager() {
                        @Override
                        protected Closeable getInnerCloseable() {
                            return null;
                        }
                    },
                    getCurrentTestName(),
                    false,
                    true);
            fail("Unexpected success: " + NamedResource.getNames(manager.getCipherFactories()));
        });
    }

    @Test
    void nonLenientSignaturesConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> {
            FactoryManager manager = SshConfigFileReader.configureSignatures(
                    new AbstractFactoryManager() {
                        @Override
                        protected Closeable getInnerCloseable() {
                            return null;
                        }
                    },
                    getCurrentTestName(),
                    false,
                    true);
            fail("Unexpected success: " + NamedResource.getNames(manager.getSignatureFactories()));
        });
    }

    @Test
    void nonLenientMacsConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> {
            FactoryManager manager = SshConfigFileReader.configureMacs(
                    new AbstractFactoryManager() {
                        @Override
                        protected Closeable getInnerCloseable() {
                            return null;
                        }
                    },
                    getCurrentTestName(),
                    false,
                    true);
            fail("Unexpected success: " + NamedResource.getNames(manager.getMacFactories()));
        });
    }

    @Test
    void configureCompressionFromStringAcceptsCombinedValues() {
        testConfigureCompressionFromStringAcceptsCombinedValues(CompressionConfigValue.class,
                e -> (e == null) ? null : e.name());
        testConfigureCompressionFromStringAcceptsCombinedValues(BuiltinCompressions.class, NamedResource.NAME_EXTRACTOR);
    }

    @Test
    void invalidDelimiter() throws IOException {
        assertThrows(StreamCorruptedException.class, () -> {
            String line = getClass().getSimpleName() + "+" + getCurrentTestName();
            try (Reader rdr = new StringReader(line)) {
                Properties props = ConfigFileReaderSupport.readConfigFile(rdr, true);
                fail("Unexpected success: " + props);
            }
        });
    }

    // SSHD-774
    @Test
    void tabDelimiter() throws IOException {
        String name = getClass().getSimpleName();
        String expected = getCurrentTestName();
        Properties props;
        try (Reader rdr = new StringReader(name + "\t" + expected)) {
            props = ConfigFileReaderSupport.readConfigFile(rdr, true);
        }

        String actual = props.getProperty(name);
        assertEquals(expected, actual, "Mismatched read configuration value");
    }

    private static <E extends Enum<E> & CompressionFactory> void testConfigureCompressionFromStringAcceptsCombinedValues(
            Class<E> facs, Function<? super E, String> configValueXformer) {
        for (E expected : facs.getEnumConstants()) {
            String value = configValueXformer.apply(expected);
            String prefix = facs.getSimpleName() + "[" + expected.name() + "][" + value + "]";
            FactoryManager manager = SshConfigFileReader.configureCompression(
                    new AbstractFactoryManager() {
                        @Override
                        protected Closeable getInnerCloseable() {
                            return null;
                        }
                    },
                    value,
                    false,
                    true);
            List<NamedFactory<Compression>> compressions = manager.getCompressionFactories();
            assertEquals(1, GenericUtils.size(compressions), prefix + "(size)");
            assertSame(expected, compressions.get(0), prefix + "[instance]");
        }
    }

    private static <M extends FactoryManager> M validateAbstractFactoryManagerConfiguration(
            M manager, Properties props, boolean lenient) {
        validateFactoryManagerCiphers(manager, props);
        validateFactoryManagerSignatures(manager, props);
        validateFactoryManagerMacs(manager, props);
        validateFactoryManagerCompressions(manager, props, lenient);
        return manager;
    }

    private static <M extends FactoryManager> M validateFactoryManagerCiphers(M manager, Properties props) {
        return validateFactoryManagerCiphers(manager,
                props.getProperty(ConfigFileReaderSupport.CIPHERS_CONFIG_PROP));
    }

    private static <M extends FactoryManager> M validateFactoryManagerCiphers(M manager, String value) {
        BuiltinCiphers.ParseResult result = BuiltinCiphers.parseCiphersList(value);
        validateFactoryManagerFactories(Cipher.class, result.getParsedFactories(), manager.getCipherFactories());
        return manager;
    }

    private static <M extends FactoryManager> M validateFactoryManagerSignatures(M manager, Properties props) {
        return validateFactoryManagerSignatures(manager,
                props.getProperty(ConfigFileReaderSupport.HOST_KEY_ALGORITHMS_CONFIG_PROP));
    }

    private static <M extends FactoryManager> M validateFactoryManagerSignatures(M manager, String value) {
        BuiltinSignatures.ParseResult result = BuiltinSignatures.parseSignatureList(value);
        validateFactoryManagerFactories(Signature.class, result.getParsedFactories(), manager.getSignatureFactories());
        return manager;
    }

    private static <M extends FactoryManager> M validateFactoryManagerMacs(M manager, Properties props) {
        return validateFactoryManagerMacs(manager,
                props.getProperty(ConfigFileReaderSupport.MACS_CONFIG_PROP));
    }

    private static <M extends FactoryManager> M validateFactoryManagerMacs(M manager, String value) {
        BuiltinMacs.ParseResult result = BuiltinMacs.parseMacsList(value);
        validateFactoryManagerFactories(Mac.class, result.getParsedFactories(), manager.getMacFactories());
        return manager;
    }

    private static <
            M extends FactoryManager> M validateFactoryManagerCompressions(M manager, Properties props, boolean lenient) {
        return validateFactoryManagerCompressions(manager,
                props.getProperty(ConfigFileReaderSupport.COMPRESSION_PROP),
                lenient);
    }

    private static <M extends FactoryManager> M validateFactoryManagerCompressions(M manager, String value, boolean lenient) {
        NamedFactory<Compression> factory = CompressionConfigValue.fromName(value);
        assertTrue(lenient || (factory != null), "Unknown compression: " + value);
        if (factory != null) {
            validateFactoryManagerFactories(Compression.class, Collections.singletonList(factory),
                    manager.getCompressionFactories());
        }
        return manager;
    }

    private static <T, F extends NamedFactory<T>> void validateFactoryManagerFactories(
            Class<T> type, List<? extends F> expected, List<? extends F> actual) {
        validateFactoryManagerSettings(type, expected, actual);
    }

    private static <R extends NamedResource> void validateFactoryManagerSettings(
            Class<?> type, List<? extends R> expected, List<? extends R> actual) {
        validateFactoryManagerSettings(type.getSimpleName(), expected, actual);
    }

    private static <R extends NamedResource> void validateFactoryManagerSettings(
            String type, List<? extends R> expected, List<? extends R> actual) {
        assertListEquals(type, expected, actual);
    }

    private static <T extends NamedResource> List<T> testParsedFactoriesList(
            List<? extends NamedResource> expected, List<T> actual, Collection<String> unsupported) {
        assertTrue(GenericUtils.isEmpty(unsupported), "Unexpected unsupported factories: " + unsupported);
        assertEquals(expected.size(), GenericUtils.size(actual), "Mismatched list size");
        for (int index = 0; index < expected.size(); index++) {
            NamedResource e = expected.get(index);
            String n1 = e.getName();
            NamedResource a = actual.get(index);
            String n2 = a.getName();
            assertEquals(n1, n2, "Mismatched name at index=" + index);
        }

        return actual;
    }

    private static <
            R extends NamedResource> Properties initNamedResourceProperties(String key, Collection<? extends R> values) {
        return initProperties(key, NamedResource.getNames(values));
    }

    private static Properties initProperties(String key, String value) {
        Properties props = new Properties();
        props.setProperty(key, value);
        return props;
    }
}
