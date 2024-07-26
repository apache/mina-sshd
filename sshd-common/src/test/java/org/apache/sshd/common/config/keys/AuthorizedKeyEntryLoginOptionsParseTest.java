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
package org.apache.sshd.common.config.keys;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class AuthorizedKeyEntryLoginOptionsParseTest extends JUnitTestSupport {
    private String value;
    private String loginPart;
    private String keyPart;
    private Map<String, String> options;

    public void initAuthorizedKeyEntryLoginOptionsParseTest(
            String value, String loginPart, String keyPart,
            Map<String, String> options) {
        this.value = value;
        this.loginPart = loginPart;
        this.keyPart = keyPart;
        this.options = options;
    }

    public static List<Object[]> parameters() {
        List<Object[]> params = new ArrayList<>();
        addData(params, "ssh-rsa AAAAB2...19Q==", "john@example.net", "from=\"*.sales.example.net,!pc.sales.example.net\"");
        addData(params, "ssh-dss AAAAC3...51R==", "example.net", "command=\"dump /home\"", "no-pty", "no-port-forwarding");
        addData(params, "ssh-dss AAAAB5...21S==", "", "permitopen=\"192.0.2.1:80\"", "permitopen=\"192.0.2.2:25\"");
        addData(params, "ssh-rsa AAAA...==", "jane@example.net", "tunnel=\"0\"", "command=\"sh /etc/netstart tun0\"");
        addData(params, "ssh-rsa AAAA1C8...32Tv==", "user@example.net", "!restrict", "command=\"uptime\"");
        addData(params, "ssh-rsa AAAA1f8...IrrC5==", "user@example.net", "restrict", "!pty", "command=\"nethack\"");
        return params;
    }

    private static void addData(List<Object[]> params, String keyData, String comment, String... comps) {
        StringBuilder sb = new StringBuilder();

        Map<String, String> optionsMap = new HashMap<>();
        for (String c : comps) {
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(c);

            int pos = c.indexOf('=');
            if (pos > 0) {
                String name = c.substring(0, pos);
                String value = GenericUtils.stripQuotes(c.substring(pos + 1)).toString();
                String prev = optionsMap.put(name, value);
                if (prev != null) {
                    optionsMap.put(name, prev + "," + value);
                }
            } else {
                optionsMap.put(c, Boolean.toString(c.charAt(0) != AuthorizedKeyEntry.BOOLEAN_OPTION_NEGATION_INDICATOR));
            }
        }

        int pos = sb.length();

        sb.append(' ').append(keyData);
        if (GenericUtils.isNotEmpty(comment)) {
            sb.append(' ').append(comment);
        }

        String value = sb.toString();
        params.add(new Object[] { value, value.substring(0, pos), value.substring(pos + 1), optionsMap });
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void resolveEntryComponents(String value, String loginPart, String keyPart, Map<String, String> options) {
        initAuthorizedKeyEntryLoginOptionsParseTest(value, loginPart, keyPart, options);
        Map.Entry<String, String> actual = AuthorizedKeyEntry.resolveEntryComponents(value);
        assertNotNull(actual, value);
        assertEquals(loginPart, actual.getKey(), "login(" + value + ")");
        assertEquals(keyPart, actual.getValue(), "remainder(" + value + ")");
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "{0}")
    public void parseLoginOptions(String value, String loginPart, String keyPart, Map<String, String> options) {
        initAuthorizedKeyEntryLoginOptionsParseTest(value, loginPart, keyPart, options);
        Map<String, String> parsed = AuthorizedKeyEntry.parseLoginOptions(loginPart);
        options.forEach((key, expected) -> {
            String actual = parsed.get(key);
            assertEquals(expected, actual, key);
        });
        assertEquals(options.size(), parsed.size(), "Mismatched size");
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + value + "]";
    }
}
