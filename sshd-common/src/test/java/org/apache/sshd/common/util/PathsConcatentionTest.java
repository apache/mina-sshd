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

package org.apache.sshd.common.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class PathsConcatentionTest extends JUnitTestSupport {
    private String p1;
    private String p2;
    private String expected;

    public void initPathsConcatentionTest(String p1, String p2, String expected) {
        this.p1 = p1;
        this.p2 = p2;
        this.expected = expected;
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // not serializing it
            private static final long serialVersionUID = 1L;

            {
                addTestCase("/a/b/c", "d/e/f", "/a/b/c/d/e/f");
                addTestCase("/a/b/c", "/d/e/f", "/a/b/c/d/e/f");
                addTestCase("/a/b/c/", "d/e/f", "/a/b/c/d/e/f");
                addTestCase("/a/b/c/", "/d/e/f", "/a/b/c/d/e/f");

                addTestCase("/", "/d", "/d");
                addTestCase("/a", "/", "/a");
                addTestCase("/", "/", "/");

                addTestCase(null, null, null);
                addTestCase(null, "", "");
                addTestCase("", null, null);
                addTestCase("", "", "");
            }

            private void addTestCase(String p1, String p2, String expected) {
                add(new Object[] { p1, p2, expected });
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "p1={0}, p2={1}, expected={2}")
    public void concatPaths(String p1, String p2, String expected) {
        initPathsConcatentionTest(p1, p2, expected);
        assertEquals(expected, SelectorUtils.concatPaths(p1, p2, '/'));
    }
}
