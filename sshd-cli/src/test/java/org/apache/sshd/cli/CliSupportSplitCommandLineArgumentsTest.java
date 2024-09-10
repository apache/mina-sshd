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

package org.apache.sshd.cli;

import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
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
public class CliSupportSplitCommandLineArgumentsTest extends BaseTestSupport {
    private String line;
    private String[] expected;

    public void initCliSupportSplitCommandLineArgumentsTest(String line, String[] expected) {
        this.line = line;
        this.expected = expected;
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // not serializing it
            private static final long serialVersionUID = 1L;

            {
                addTestCase(null, GenericUtils.EMPTY_STRING_ARRAY);
                addTestCase("", GenericUtils.EMPTY_STRING_ARRAY);
                addTestCase("   ", GenericUtils.EMPTY_STRING_ARRAY);
                addPaddedTestCase("hello", "hello");
                addPaddedTestCase("hello world", "hello", "world");

                for (int index = 0; index < GenericUtils.QUOTES.length(); index++) {
                    char delim = GenericUtils.QUOTES.charAt(index);
                    addPaddedTestCase(delim + "hello world" + delim, "hello world");
                    addPaddedTestCase(delim + "hello" + delim + " world", "hello", "world");
                    addPaddedTestCase("hello " + delim + "world" + delim, "hello", "world");
                    addPaddedTestCase(delim + "hello" + delim + " " + delim + "world" + delim, "hello", "world");
                }
            }

            private void addPaddedTestCase(String line, String... expected) {
                addTestCase(line, expected);
                addTestCase("    " + line, expected);
                addTestCase(line + "    ", expected);
                addTestCase("    " + line + "    ", expected);
            }

            private void addTestCase(String line, String... expected) {
                add(new Object[] { line, expected });
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "<{0}>")
    public void splitCommandLineArguments(String line, String[] expected) {
        initCliSupportSplitCommandLineArgumentsTest(line, expected);
        String[] actual = CliSupport.splitCommandLineArguments(line);
        assertArrayEquals(expected, actual);
    }
}
