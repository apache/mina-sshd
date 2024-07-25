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

package org.apache.sshd.server.command;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase") // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class CommandFactorySplitterTest extends JUnitTestSupport {
    private String command;
    private List<String> expected;

    public void initCommandFactorySplitterTest(String command, List<String> expected) {
        this.command = command;
        this.expected = expected;
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // not serializing it
            private static final long serialVersionUID = 1L;

            {
                addTestCase(null, Collections.emptyList());
                addTestCase("", Collections.emptyList());
                addTestCase("ls", Collections.singletonList("ls"));
                addTestCase("ls -l -a --sort /tmp",
                        Arrays.asList("ls", "-l", "-a", "--sort", "/tmp"));
                addTestCase("ssh   -o      StrictHostKeyChecking=no  user@1.2.3.4",
                        Arrays.asList("ssh", "-o", "StrictHostKeyChecking=no", "user@1.2.3.4"));
                addTestCase("rm -rvf '/tmp/Single Quoted/with spaces'",
                        Arrays.asList("rm", "-rvf", "/tmp/Single Quoted/with spaces"));
                addTestCase("ls -la \"/tmp/Double Quoted with spaces\"",
                        Arrays.asList("ls", "-la", "/tmp/Double Quoted with spaces"));
                addTestCase("doWith'Quote\"in'middle something",
                        Arrays.asList("doWith'Quote\"in'middle", "something"));
                addTestCase("'Single quoted' first",
                        Arrays.asList("Single quoted", "first"));
                addTestCase("\"Double quoted\" first",
                        Arrays.asList("Double quoted", "first"));
            }

            private void addTestCase(String cmd, List<String> elems) {
                add(new Object[] { cmd, elems });
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "cmd={0}")
    public void splitter(String command, List<String> expected) {
        initCommandFactorySplitterTest(command, expected);
        List<String> actual = CommandFactory.split(command);
        assertListEquals(command, expected, actual);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + command + "]";
    }
}
