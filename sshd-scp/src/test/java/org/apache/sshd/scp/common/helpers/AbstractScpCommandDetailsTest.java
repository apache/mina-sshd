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

package org.apache.sshd.scp.common.helpers;

import java.lang.reflect.Constructor;
import java.util.stream.Stream;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * @param  <C> Generic {@link AbstractScpCommandDetails} type
 *
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase") // see https://github.com/junit-team/junit/wiki/Parameterized-tests
class AbstractScpCommandDetailsTest<C extends AbstractScpCommandDetails> extends JUnitTestSupport {

    static Stream<Arguments> parameters() {
        return Stream.of( //
                Arguments.of("T123456789 0 987654321 0", ScpTimestampCommandDetails.class),
                Arguments.of("C0644 12345 file", ScpReceiveFileCommandDetails.class),
                Arguments.of("D0755 0 dir", ScpReceiveDirCommandDetails.class),
                Arguments.of(ScpDirEndCommandDetails.HEADER, ScpDirEndCommandDetails.class));
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "cmd={0}")
    void headerEquality(String header, Class<C> cmdClass) throws Exception {
        Constructor<C> ctor = cmdClass.getDeclaredConstructor(String.class);
        C details = ctor.newInstance(header);
        assertEquals(header, details.toHeader());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "cmd={0}")
    void detailsEquality(String header, Class<C> cmdClass) throws Exception {
        Constructor<C> ctor = cmdClass.getDeclaredConstructor(String.class);
        C d1 = ctor.newInstance(header);
        C d2 = ctor.newInstance(header);
        assertEquals(d1.hashCode(), d2.hashCode(), "HASH ?");
        assertEquals(d1, d2, "EQ ?");
    }
}
