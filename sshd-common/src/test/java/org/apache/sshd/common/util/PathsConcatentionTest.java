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

import java.util.stream.Stream;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
class PathsConcatentionTest extends JUnitTestSupport {

    public static Stream<Arguments> parameters() {
        return Stream.of( //
                Arguments.of("/a/b/c", "d/e/f", "/a/b/c/d/e/f"), //
                Arguments.of("/a/b/c", "/d/e/f", "/a/b/c/d/e/f"), //
                Arguments.of("/a/b/c/", "d/e/f", "/a/b/c/d/e/f"), //
                Arguments.of("/a/b/c/", "/d/e/f", "/a/b/c/d/e/f"),

                Arguments.of("/", "/d", "/d"), //
                Arguments.of("/a", "/", "/a"), //
                Arguments.of("/", "/", "/"),

                Arguments.of(null, null, null), //
                Arguments.of(null, "", ""), //
                Arguments.of("", null, null), //
                Arguments.of("", "", ""));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "p1={0}, p2={1}, expected={2}")
    void concatPaths(String p1, String p2, String expected) {
        assertEquals(expected, SelectorUtils.concatPaths(p1, p2, '/'));
    }
}
