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
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.MapEntryUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
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
public class HostConfigEntryTest extends JUnitTestSupport {
    public HostConfigEntryTest() {
        super();
    }

    private void expect(String hostname, int port, String username, HostConfigEntry resolved) throws Exception {
        assertEquals(hostname, resolved.getHostName());
        assertEquals(port, resolved.getPort());
        assertEquals(username, resolved.getUsername());
        assertEquals(hostname, resolved.getProperty(HostConfigEntry.HOST_NAME_CONFIG_PROP));
        assertEquals(Integer.toString(port), resolved.getProperty(HostConfigEntry.PORT_CONFIG_PROP));
        assertEquals(username, resolved.getProperty(HostConfigEntry.USER_CONFIG_PROP));
    }

    @Test
    public void testSetTwice() throws Exception {
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
    public void testArgumentsOverrideConfig() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo.example.com", null, 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 2022, null, "testuser", null, null);
        expect("foo.example.com", 2022, "testuser", resolved);
    }

    @Test
    public void testConfigSetsHostname() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo.example.com", "bar.example.com", 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 2022, null, "testuser", null, null);
        expect("bar.example.com", 2022, "testuser", resolved);
    }

    @Test
    public void testWildcardHostname() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo*", null, 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 2022, null, "testuser", null, null);
        expect("foo.example.com", 2022, "testuser", resolved);
    }

    @Test
    public void testDefaults() throws Exception {
        HostConfigEntry entry = new HostConfigEntry("foo*", "bar.example.com", 22, "test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo", 0, null, "", null, null);
        expect("bar.example.com", 22, "test", resolved);
    }

    @Test
    public void testDefaultDefaults() throws Exception {
        HostConfigEntry entry = new HostConfigEntry();
        entry.setHost("foo*");
        entry.setUsername("test");
        HostConfigEntry resolved = HostConfigEntry.toHostConfigEntryResolver(Collections.singleton(entry))
                .resolveEffectiveHost("foo.example.com", 0, null, "", null, null);
        expect("foo.example.com", 22, "test", resolved);
    }

    @Test
    public void testCoalescing() throws Exception {
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
    public void testCoalescingFirstValue() throws Exception {
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
    public void testCoalescingIdentityFile() throws Exception {
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

    @Test
    public void testNegatingPatternOverridesAll() {
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
            assertFalse("Unexpected match for " + patterns, HostPatternsHolder.isHostMatch(testHost, 0, patterns));
            Collections.shuffle(patterns);
        }
    }

    @Test
    public void testHostWildcardPatternMatching() {
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
    public void testIPAddressWildcardPatternMatching() {
        StringBuilder sb = new StringBuilder().append("10.0.0.");
        int sbLen = sb.length();

        Pattern pattern = HostPatternsHolder.toPattern(sb.append(HostPatternsHolder.WILDCARD_PATTERN)).getPattern();
        for (int v = 0; v <= 255; v++) {
            sb.setLength(sbLen); // start from scratch
            sb.append(v);

            String address = sb.toString();
            assertTrue("No match for " + address, HostPatternsHolder.isHostMatch(address, pattern));
        }
    }

    @Test
    public void testHostSingleCharPatternMatching() {
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
    public void testIPAddressSingleCharPatternMatching() {
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
            assertTrue("No match for " + address + " on pattern=" + pattern,
                    HostPatternsHolder.isHostMatch(address, 0, Collections.singletonList(pp)));
        }
    }

    @Test
    public void testIPv6AddressSingleCharPatternMatching() {
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
            assertTrue("No match for " + address + " on pattern=" + pattern,
                    HostPatternsHolder.isHostMatch(address, 0, Collections.singletonList(pp)));
        }
    }

    @Test
    public void testIsValidPatternChar() {
        for (char ch = '\0'; ch <= ' '; ch++) {
            assertFalse("Unexpected valid character (0x" + Integer.toHexString(ch & 0xFF) + ")",
                    HostPatternsHolder.isValidPatternChar(ch));
        }

        for (char ch = 'a'; ch <= 'z'; ch++) {
            assertTrue("Valid character not recognized: " + Character.toString(ch), HostPatternsHolder.isValidPatternChar(ch));
        }

        for (char ch = 'A'; ch <= 'Z'; ch++) {
            assertTrue("Valid character not recognized: " + Character.toString(ch), HostPatternsHolder.isValidPatternChar(ch));
        }

        for (char ch = '0'; ch <= '9'; ch++) {
            assertTrue("Valid character not recognized: " + Character.toString(ch), HostPatternsHolder.isValidPatternChar(ch));
        }

        for (char ch : new char[] {
                '-', '_', '.', HostPatternsHolder.SINGLE_CHAR_PATTERN, HostPatternsHolder.WILDCARD_PATTERN }) {
            assertTrue("Valid character not recognized: " + Character.toString(ch), HostPatternsHolder.isValidPatternChar(ch));
        }

        for (char ch : new char[] {
                '(', ')', '{', '}', '[', ']', '@',
                '#', '$', '^', '&', '~', '<', '>',
                ',', '/', '\\', '\'', '"', ';'
        }) {
            assertFalse("Unexpected valid character: " + Character.toString(ch), HostPatternsHolder.isValidPatternChar(ch));
        }

        for (char ch = 0x7E; ch <= 0xFF; ch++) {
            assertFalse("Unexpected valid character (0x" + Integer.toHexString(ch & 0xFF) + ")",
                    HostPatternsHolder.isValidPatternChar(ch));
        }
    }

    @Test
    public void testReadSimpleHostsConfigEntries() throws IOException {
        validateHostConfigEntries(readHostConfigEntries());
    }

    @Test
    public void testReadGlobalHostsConfigEntries() throws IOException {
        List<HostConfigEntry> entries = validateHostConfigEntries(readHostConfigEntries());
        assertTrue("Not enough entries read", GenericUtils.size(entries) > 1);

        // global entry MUST be 1st one
        HostConfigEntry globalEntry = entries.get(0);
        assertEquals("Mismatched global entry pattern", HostPatternsHolder.ALL_HOSTS_PATTERN, globalEntry.getHost());

        for (int index = 1; index < entries.size(); index++) {
            HostConfigEntry entry = entries.get(index);
            assertFalse("No properties for " + entry, MapEntryUtils.isEmpty(entry.getProperties()));
            boolean noHostName = GenericUtils.isEmpty(entry.getHostName());
            boolean noPort = entry.getPort() <= 0;
            boolean noUsername = GenericUtils.isEmpty(entry.getUsername());
            boolean noIdentities = GenericUtils.isEmpty(entry.getIdentities());
            if (index == 1) {
                assertFalse("No username for " + entry, noUsername);
            } else {
                assertTrue("Unexpected username for " + entry, noUsername);
            }
            if (index == 2) {
                assertFalse("No target port for " + entry, noPort);
            } else {
                assertTrue("Unexpected target port for " + entry, noPort);
            }
            if (index == 3) {
                assertFalse("No target host for " + entry, noHostName);
            } else {
                assertTrue("Unexpected target host for " + entry, noHostName);
            }
            if (index == 4) {
                assertFalse("No identities for " + entry, noIdentities);
            } else {
                assertTrue("Unexpected identity for " + entry, noIdentities);
            }
        }
    }

    @Test
    public void testReadMultipleHostPatterns() throws IOException {
        List<HostConfigEntry> entries = validateHostConfigEntries(readHostConfigEntries());
        assertEquals("Mismatched number of entries", 1, GenericUtils.size(entries));
        assertEquals("Mismatched number of patterns", 3, GenericUtils.size(entries.get(0).getPatterns()));
    }

    @Test
    public void testResolveIdentityFilePath() throws Exception {
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
        assertFalse("No entries", GenericUtils.isEmpty(entries));

        for (HostConfigEntry entry : entries) {
            assertFalse("No pattern for " + entry, GenericUtils.isEmpty(entry.getHost()));
            assertFalse("No extra properties for " + entry, MapEntryUtils.isEmpty(entry.getProperties()));
        }

        return entries;
    }

    private List<HostConfigEntry> readHostConfigEntries() throws IOException {
        return readHostConfigEntries(getCurrentTestName() + ".config.txt");
    }

    private List<HostConfigEntry> readHostConfigEntries(String resourceName) throws IOException {
        URL url = getClass().getResource(resourceName);
        assertNotNull("Missing resource " + resourceName, url);
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
