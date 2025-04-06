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

package org.apache.sshd.scp.common;

import java.util.stream.Stream;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
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
class ScpLocationParsingTest extends JUnitTestSupport {

    static Stream<Arguments> parameters() {
        return Stream.of( //
                Arguments.of(null, null), //
                Arguments.of("", null), //
                Arguments.of("/local/path/value", new ScpLocation(null, null, "/local/path/value")),
                Arguments.of("user@host:/remote/path/value", new ScpLocation("user", "host", "/remote/path/value")),
                Arguments.of("scp://user@host/remote/path/value", new ScpLocation("user", "host", "/remote/path/value")),
                Arguments.of("scp://user@host:22/remote/path/value", new ScpLocation("user", "host", "/remote/path/value")),
                Arguments.of("scp://user@host:2222/remote/path/value",
                        new ScpLocation("user", "host", 2222, "/remote/path/value")));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "value={0}")
    void locationParsing(String value, ScpLocation location) {
        ScpLocation actual = ScpLocation.parse(value);
        assertEquals(location, actual);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "value={0}")
    void locationToString(String value, ScpLocation location) {
        Assumptions.assumeTrue(location != null, "No expected value to compate");
        Assumptions.assumeTrue(location.isLocal() || (location.resolvePort() != SshConstants.DEFAULT_PORT),
                "Default port being used");
        String spec = location.toString();
        assertEquals(value, spec);
    }
}
