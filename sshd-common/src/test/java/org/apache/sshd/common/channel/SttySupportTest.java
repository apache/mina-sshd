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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
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
        String stty;
        try (InputStream s = ValidateUtils.checkNotNull(
                getClass().getResourceAsStream(resourceName), "Missing %s", resourceName);
             Reader r = new InputStreamReader(s, StandardCharsets.UTF_8)) {
            char[] buf = new char[8192];
            int len = r.read(buf);
            stty = new String(buf, 0, len);
        }

        Map<PtyMode, Integer> modes = SttySupport.parsePtyModes(stty);
        System.err.println(modes);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + resourceName + "]";
    }
}
