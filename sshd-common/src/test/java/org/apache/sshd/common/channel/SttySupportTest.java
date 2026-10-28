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
package org.apache.sshd.common.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class SttySupportTest extends JUnitTestSupport {
    private String resourceName;

    public void initSttySupportTest(String resourceName) {
        this.resourceName = resourceName;
    }

    public static List<Object[]> parameters() {
        return parameterize(Arrays.asList("stty-output-1.txt", "stty-output-2.txt"));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void parseSttyOutput(String resourceName) throws Exception {
        initSttySupportTest(resourceName);
        Map<PtyMode, Integer> modes = SttySupport.parsePtyModes(readSttyOutput(resourceName));
        System.err.println(modes);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void parseSttyOutputIndependentOfDefaultLocale(String resourceName) throws Exception {
        initSttySupportTest(resourceName);
        String stty = readSttyOutput(resourceName);
        Map<PtyMode, Integer> expected = SttySupport.parsePtyModes(stty);

        Map<PtyMode, Integer> turkish;
        Locale previous = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            turkish = SttySupport.parsePtyModes(stty);
        } finally {
            Locale.setDefault(previous);
        }

        assertEquals(expected, turkish, "Modes parsed under tr-TR locale");
        assertTrue(turkish.containsKey(PtyMode.ISIG), "ISIG missing under tr-TR locale");
        assertTrue(turkish.containsKey(PtyMode.ICANON), "ICANON missing under tr-TR locale");
        assertTrue(turkish.containsKey(PtyMode.VINTR), "VINTR missing under tr-TR locale");
    }

    private String readSttyOutput(String resourceName) throws IOException {
        try (InputStream s = ValidateUtils.checkNotNull(
                getClass().getResourceAsStream(resourceName), "Missing %s", resourceName);
             Reader r = new InputStreamReader(s, StandardCharsets.UTF_8)) {
            char[] buf = new char[8192];
            int len = r.read(buf);
            return new String(buf, 0, len);
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + resourceName + "]";
    }
}
