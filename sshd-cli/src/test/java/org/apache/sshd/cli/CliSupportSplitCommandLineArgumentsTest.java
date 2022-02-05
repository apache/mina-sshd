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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
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
@Category({ NoIoTestCase.class })
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
public class CliSupportSplitCommandLineArgumentsTest extends BaseTestSupport {
    private final String line;
    private final String[] expected;

    public CliSupportSplitCommandLineArgumentsTest(String line, String[] expected) {
        this.line = line;
        this.expected = expected;
    }

    @Parameters(name = "{0}")
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

    @Test
    public void testSplitCommandLineArguments() {
        String[] actual = CliSupport.splitCommandLineArguments(line);
        assertArrayEquals(expected, actual);
    }
}
