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

package org.apache.sshd.client.config.hosts;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class HostConfigEntryTest extends JUnitTestSupport {

    private void expect(String hostname, int port, String username, HostConfigEntry resolved) throws Exception {
        assertEquals(hostname, resolved.getHostName());
        assertEquals(port, resolved.getPort());
        assertEquals(username, resolved.getUsername());
        assertEquals(hostname, resolved.getProperty(HostConfigEntry.HOST_NAME_CONFIG_PROP));
        assertEquals(Integer.toString(port), resolved.getProperty(HostConfigEntry.PORT_CONFIG_PROP));
        assertEquals(username, resolved.getProperty(HostConfigEntry.USER_CONFIG_PROP));
    }

    @Test
    void setTwice() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo", "foo.example.com", 22, "test");
        entry.setProperties(null);
        entry.setHost("bar");
        entry.setHostName("bar.example.com");
        entry.setPort(2022);
        entry.setUsername("test2");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("bar", 0, null, null, null, null);
        expect("bar.example.com", 2022, "test2", resolved);
    }

    @Test
    void argumentsOverrideConfig() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo.example.com", null, 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 2022, null, "testuser", null, null);
        expect("foo.example.com", 2022, "testuser", resolved);
    }

    @Test
    void configSetsHostname() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo.example.com", "bar.example.com", 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 2022, null, "testuser", null, null);
        expect("bar.example.com", 2022, "testuser", resolved);
    }

    @Test
    void wildcardHostname() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo*", null, 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 2022, null, "testuser", null, null);
        expect("foo.example.com", 2022, "testuser", resolved);
    }

    @Test
    void defaults() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo*", "bar.example.com", 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo", 0, null, "", null, null);
        expect("bar.example.com", 22, "test", resolved);
    }

    @Test
    void defaultDefaults() throws Exception {
        HostConfigEntry entry = new HostConfigEntry();
        entry.setHost("foo*");
        entry.setUsername("test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 0, null, "", null, null);
        expect("foo.example.com", 22, "test", resolved);
    }

    @Test
    void coalescing() throws Exception {
        HostConfigEntry first = new HostConfigEntry();
        first.setHost("foo*");
        first.setHostName("bar.example.com");
        HostConfigEntry second = new HostConfigEntry();
        second.setHost("foo");
        second.setUsername("test1");
        second.setPort(2022);
        HostConfigEntry third = new HostConfigEntry();
        third.setHost("foo2");
        third.setUsername("test2");
        third.setPort(2023);
        HostConfigEntryResolver resolver = HostConfigEntry.toHostConfigEntryResolver(GenericUtils.asList(first, second, third));
        HostConfigEntry resolved = resolver.resolveEffectiveHost("foo", 0, null, "", null, null);
        expect("bar.example.com", 2022, "test1", resolved);
        resolved = resolver.resolveEffectiveHost("foo2", 0, null, "", null, null);
        expect("bar.example.com", 2023, "test2", resolved);
    }

    @Test
    void coalescingFirstValue() throws Exception {
        HostConfigEntry first = new HostConfigEntry();
        first.setHost("fo*");
        first.setHostName("bar.example.com");
        HostConfigEntry second = new HostConfigEntry("foo", "foo.example.com", 2022, "test1");
        HostConfigEntry third = new HostConfigEntry("foo*", "foo2.example.com", 2023, "test2");
        HostConfigEntryResolver resolver = HostConfigEntry.toHostConfigEntryResolver(GenericUtils.asList(first, second, third));
        HostConfigEntry resolved = resolver.resolveEffectiveHost("foo", 0, null, "", null, null);
        expect("bar.example.com", 2022, "test1", resolved);
        resolved = resolver.resolveEffectiveHost("foo2", 0, null, "", null, null);
        expect("bar.example.com", 2023, "test2", resolved);
    }

    @Test
    void coalescingIdentityFile() throws Exception {
        HostConfigEntry first = new HostConfigEntry();
        first.setHost("fo*");
        first.setHostName("bar.example.com");
        first.setIdentities(Collections.singleton("xFile"));
        HostConfigEntry second = new HostConfigEntry("foo", "foo.example.com", 2022, "test1");
        second.setIdentities(GenericUtils.asList("bFile", "yFile"));
        HostConfigEntry third = new HostConfigEntry("foo*", "foo2.example.com", 2023, "test2");
        third.setIdentities(Collections.singleton("dFile"));
        HostConfigEntryResolver resolver = HostConfigEntry.toHostConfigEntryResolver(GenericUtils.asList(first, second, third));
        HostConfigEntry resolved = resolver.resolveEffectiveHost("foo", 0, null, "", null, null);
        expect("bar.example.com", 2022, "test1", resolved);
        assertEquals("[xFile, bFile, yFile, dFile]", resolved.getIdentities().toString());
        assertEquals("xFile,bFile,yFile,dFile", resolved.getProperty(HostConfigEntry.IDENTITY_FILE_CONFIG_PROP));
        resolved = resolver.resolveEffectiveHost("foo2", 0, null, "", null, null);
        expect("bar.example.com", 2023, "test2", resolved);
        assertEquals("[xFile, dFile]", resolved.getIdentities().toString());
        assertEquals("xFile,dFile", resolved.getProperty(HostConfigEntry.IDENTITY_FILE_CONFIG_PROP));
    }

    // See GH-351
    @Test
    void proxyJump() throws Exception {
        HostConfigEntry bastion = new HostConfigEntry();
        bastion.setHost("bastion");
        bastion.setHostName("1.2.3.4");
        bastion.setUsername("username");
        bastion.setIdentities(Collections.singleton("yFile"));
        HostConfigEntry server = new HostConfigEntry();
        server.setHost("server*");
        server.setProxyJump("bastion");
        HostConfigEntryResolver resolver = HostConfigEntry.toHostConfigEntryResolver(GenericUtils.asList(bastion, server));
        HostConfigEntry resolved = resolver.resolveEffectiveHost("server1", 0, null, "someone", null, null);
        expect("server1", 22, "someone", resolved);
        Collection<String> identities = resolved.getIdentities();
        assertTrue(identities == null || identities.isEmpty(), "Unexpected configured identities " + identities);
        String identityProp = resolved.getProperty(HostConfigEntry.IDENTITY_FILE_CONFIG_PROP);
        assertNull(identityProp, "Unexpected IdentityFile property");
        // Same handling as in SshClient.parseProxyJumps()
        String proxy = resolved.getProperty(HostConfigEntry.PROXY_JUMP_CONFIG_PROP);
        assertEquals("bastion", proxy);
        URI uri = URI.create("ssh://" + proxy);
        resolved = resolver.resolveEffectiveHost(uri.getHost(), uri.getPort(), null, uri.getUserInfo(), null, null);
        expect("1.2.3.4", 22, "username", resolved);
        identities = resolved.getIdentities();
        assertNotNull(identities, "Should have identities");
        assertEquals("[yFile]", identities.toString());
        identityProp = resolved.getProperty(HostConfigEntry.IDENTITY_FILE_CONFIG_PROP);
        assertNotNull(identityProp, "Should have IdentityFile property");
        assertEquals("yFile", identityProp);
    }

    @Test
    void negatingPatternOverridesAll() {
        String testHost = "37.77.34.7";
        String[] elements = GenericUtils.split(testHost, '.');
        StringBuilder sb = new StringBuilder(testHost.length() + Byte.SIZE);
        List<HostPatternValue> patterns = new ArrayList<>(elements.length + 1);
        // all wildcard patterns are not negated - only the actual host
        patterns.add(HostPatternsHolder.toPattern(Character.toString(HostPatternsHolder.NEGATION_CHAR_PATTERN) + testHost));

        for (int i = 0; i < elements.length; i++) {
            sb.setLength(0);

            for (int j = 0; j < elements.length; j++) {
                if (j > 0) {
                    sb.append('.');
                }
                if (i == j) {
                    sb.append(HostPatternsHolder.WILDCARD_PATTERN);
                } else {
                    sb.append(elements[j]);
                }
            }

            patterns.add(HostPatternsHolder.toPattern(sb));
        }

        for (int index = 0; index < patterns.size(); index++) {
            assertFalse(HostPatternsHolder.isHostMatch(testHost, 0, patterns), "Unexpected match for " + patterns);
            Collections.shuffle(patterns);
        }
    }

    @Test
    void hostWildcardPatternMatching() {
        String pkgName = getClass().getPackage().getName();
        String[] elements = GenericUtils.split(pkgName, '.');
        StringBuilder sb = new StringBuilder(pkgName.length() + Long.SIZE + 1).append(HostPatternsHolder.WILDCARD_PATTERN);
        for (int index = elements.length - 1; index >= 0; index--) {
            sb.append('.').append(elements[index]);
        }

        String value = sb.toString();
        HostPatternValue pp = HostPatternsHolder.toPattern(value);
        Pattern pattern = pp.getPattern();
        String domain = value.substring(1); // chomp the wildcard prefix
        for (String host : new String[] {
                getClass().getSimpleName(),
                getCurrentTestName(),
                getClass().getSimpleName() + "-" + getCurrentTestName(),
                getClass().getSimpleName() + "." + getCurrentTestName(),
        }) {
            sb.setLength(0); // start from scratch
            sb.append(host).append(domain);

            testCaseInsensitivePatternMatching(sb.toString(), pattern, true);
        }
    }

    @Test
    void iPAddressWildcardPatternMatching() {
        StringBuilder sb = new StringBuilder().append("10.0.0.");
        int sbLen = sb.length();

        Pattern pattern = HostPatternsHolder.toPattern(sb.append(HostPatternsHolder.WILDCARD_PATTERN)).getPattern();
        for (int v = 0; v <= 255; v++) {
            sb.setLength(sbLen); // start from scratch
            sb.append(v);

            String address = sb.toString();
            assertTrue(HostPatternsHolder.isHostMatch(address, pattern), "No match for " + address);
        }
    }

    @Test
    void hostSingleCharPatternMatching() {
        String value = getCurrentTestName();
        StringBuilder sb = new StringBuilder(value);
        for (boolean restoreOriginal : new boolean[] { true, false }) {
            for (int index = 0; index < value.length(); index++) {
                sb.setCharAt(index, HostPatternsHolder.SINGLE_CHAR_PATTERN);
                testCaseInsensitivePatternMatching(value, HostPatternsHolder.toPattern(sb.toString()).getPattern(), true);
                if (restoreOriginal) {
                    sb.setCharAt(index, value.charAt(index));
                }
            }
        }
    }

    @Test
    void iPAddressSingleCharPatternMatching() {
        StringBuilder sb = new StringBuilder().append("10.0.0.");
        int sbLen = sb.length();

        for (int v = 0; v <= 255; v++) {
            sb.setLength(sbLen); // start from scratch
            sb.append(v);

            String address = sb.toString();
            // replace the added digits with single char pattern
            for (int index = sbLen; index < sb.length(); index++) {
                sb.setCharAt(index, HostPatternsHolder.SINGLE_CHAR_PATTERN);
            }

            String pattern = sb.toString();
            HostPatternValue pp = HostPatternsHolder.toPattern(pattern);
            assertTrue(HostPatternsHolder.isHostMatch(address, 0, Collections.singletonList(pp)),
                    "No match for " + address + " on pattern=" + pattern);
        }
    }

    @Test
    void iPv6AddressSingleCharPatternMatching() {
        StringBuilder sb = new StringBuilder().append("fe80::7780:db3:a57:6a9");
        int sbLen = sb.length();

        for (int v = 0; v <= 255; v++) {
            sb.setLength(sbLen); // start from scratch
            sb.append(v);

            String address = sb.toString();
            // replace the added digits with single char pattern
            for (int index = sbLen; index < sb.length(); index++) {
                sb.setCharAt(index, HostPatternsHolder.SINGLE_CHAR_PATTERN);
            }

            String pattern = sb.toString();
            HostPatternValue pp = HostPatternsHolder.toPattern(pattern);
            assertTrue(HostPatternsHolder.isHostMatch(address, 0, Collections.singletonList(pp)),
                    "No match for " + address + " on pattern=" + pattern);
        }
    }

    @Test
    void isValidPatternChar() {
        for (char ch = '\0'; ch <= ' '; ch++) {
            assertFalse(HostPatternsHolder.isValidPatternChar(ch),
                    "Unexpected valid character (0x" + Integer.toHexString(ch & 0xFF) + ")");
        }

        for (char ch = 'a'; ch <= 'z'; ch++) {
            assertTrue(HostPatternsHolder.isValidPatternChar(ch), "Valid character not recognized: " + Character.toString(ch));
        }

        for (char ch = 'A'; ch <= 'Z'; ch++) {
            assertTrue(HostPatternsHolder.isValidPatternChar(ch), "Valid character not recognized: " + Character.toString(ch));
        }

        for (char ch = '0'; ch <= '9'; ch++) {
            assertTrue(HostPatternsHolder.isValidPatternChar(ch), "Valid character not recognized: " + Character.toString(ch));
        }

        for (char ch : new char[] {
                '-', '_', '.', HostPatternsHolder.SINGLE_CHAR_PATTERN, HostPatternsHolder.WILDCARD_PATTERN }) {
            assertTrue(HostPatternsHolder.isValidPatternChar(ch), "Valid character not recognized: " + Character.toString(ch));
        }

        for (char ch : new char[] {
                '(', ')', '{', '}', '[', ']', '@',
                '#', '$', '^', '&', '~', '<', '>',
                ',', '/', '\\', '\'', '"', ';'
        }) {
            assertFalse(HostPatternsHolder.isValidPatternChar(ch), "Unexpected valid character: " + Character.toString(ch));
        }

        for (char ch = 0x7E; ch <= 0xFF; ch++) {
            assertFalse(HostPatternsHolder.isValidPatternChar(ch),
                    "Unexpected valid character (0x" + Integer.toHexString(ch & 0xFF) + ")");
        }
    }

    @Test
    void readSimpleHostsConfigEntries() throws IOException {
        validateHostConfigEntries(readHostConfigEntries());
    }

    @Test
    void readGlobalHostsConfigEntries() throws IOException {
        List<HostConfigEntry> entries = validateHostConfigEntries(readHostConfigEntries());
        assertTrue(GenericUtils.size(entries) > 1, "Not enough entries read");

        // global entry MUST be 1st one
        HostConfigEntry globalEntry = entries.get(0);
        assertEquals(HostPatternsHolder.ALL_HOSTS_PATTERN, globalEntry.getHost(), "Mismatched global entry pattern");

        for (int index = 1; index < entries.size(); index++) {
            HostConfigEntry entry = entries.get(index);
            assertFalse(MapEntryUtils.isEmpty(entry.getProperties()), "No properties for " + entry);
            boolean noHostName = GenericUtils.isEmpty(entry.getHostName());
            boolean noPort = entry.getPort() <= 0;
            boolean noUsername = GenericUtils.isEmpty(entry.getUsername());
            boolean noIdentities = GenericUtils.isEmpty(entry.getIdentities());
            if (index == 1) {
                assertFalse(noUsername, "No username for " + entry);
            } else {
                assertTrue(noUsername, "Unexpected username for " + entry);
            }
            if (index == 2) {
                assertFalse(noPort, "No target port for " + entry);
            } else {
                assertTrue(noPort, "Unexpected target port for " + entry);
            }
            if (index == 3) {
                assertFalse(noHostName, "No target host for " + entry);
            } else {
                assertTrue(noHostName, "Unexpected target host for " + entry);
            }
            if (index == 4) {
                assertFalse(noIdentities, "No identities for " + entry);
            } else {
                assertTrue(noIdentities, "Unexpected identity for " + entry);
            }
        }
    }

    @Test
    void readMultipleHostPatterns() throws IOException {
        List<HostConfigEntry> entries = validateHostConfigEntries(readHostConfigEntries());
        assertEquals(1, GenericUtils.size(entries), "Mismatched number of entries");
        assertEquals(3, GenericUtils.size(entries.get(0).getPatterns()), "Mismatched number of patterns");
    }

    @Test
    void resolveIdentityFilePath() throws Exception {
        final String hostValue = getClass().getSimpleName();
        final int portValue = 7365;
        final String userValue = getCurrentTestName();

        Exception err = null;
        for (String pattern : new String[] {
                "~/.ssh/%h.key",
                "%d/.ssh/%h.key",
                "/home/%u/.ssh/id_rsa_%p",
                "/home/%u/.ssh/id_%r_rsa",
                "/home/%u/.ssh/%h/%l.key"
        }) {
            try {
                String result = HostConfigEntry.resolveIdentityFilePath(pattern, hostValue, portValue, userValue);
                System.out.append('\t').append(pattern).append(" => ").println(result);
            } catch (Exception e) {
                System.err.append("Failed (").append(e.getClass().getSimpleName())
                        .append(") to process pattern=").append(pattern)
                        .append(": ").println(e.getMessage());
                err = e;
            }
        }

        if (err != null) {
            throw err;
        }
    }

    private static <C extends Collection<HostConfigEntry>> C validateHostConfigEntries(C entries) {
        assertFalse(GenericUtils.isEmpty(entries), "No entries");

        for (HostConfigEntry entry : entries) {
            assertFalse(GenericUtils.isEmpty(entry.getHost()), "No pattern for " + entry);
            assertFalse(MapEntryUtils.isEmpty(entry.getProperties()), "No extra properties for " + entry);
        }

        return entries;
    }

    private List<HostConfigEntry> readHostConfigEntries() throws IOException {
        return readHostConfigEntries(getCurrentTestName() + ".config.txt");
    }

    private List<HostConfigEntry> readHostConfigEntries(String resourceName) throws IOException {
        URL url = getClass().getResource(resourceName);
        assertNotNull(url, "Missing resource " + resourceName);
        return HostConfigEntry.readHostConfigEntries(url);
    }

    private static void testCaseInsensitivePatternMatching(String value, Pattern pattern, boolean expected) {
        for (int index = 0; index < value.length(); index++) {
            boolean actual = HostPatternsHolder.isHostMatch(value, pattern);
            assertEquals("Mismatched match result for " + value + " on pattern=" + pattern.pattern(), expected, actual);
            value = shuffleCase(value);
        }
    }
}
