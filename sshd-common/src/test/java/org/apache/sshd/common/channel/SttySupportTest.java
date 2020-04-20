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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class SttySupportTest extends JUnitTestSupport {
    private final String resourceName;

    public SttySupportTest(String resourceName) {
        this.resourceName = resourceName;
    }

    @Parameters(name = "{0}")
    public static List<Object[]> parameters() {
        return parameterize(Arrays.asList("stty-output-1.txt", "stty-output-2.txt"));
    }

    @Test
    public void testParseSttyOutput() throws Exception {
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
