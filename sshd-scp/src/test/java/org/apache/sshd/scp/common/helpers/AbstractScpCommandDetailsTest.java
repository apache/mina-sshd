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
 * @param  <C> Generic {@link AbstractScpCommandDetails} type
 *
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase") // see https://github.com/junit-team/junit/wiki/Parameterized-tests
public class AbstractScpCommandDetailsTest<C extends AbstractScpCommandDetails> extends JUnitTestSupport {
    private String header;
    private Constructor<C> ctor;

    public void initAbstractScpCommandDetailsTest(String header, Class<C> cmdClass) throws Exception {
        this.header = header;
        this.ctor = cmdClass.getDeclaredConstructor(String.class);
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // not serializing it
            private static final long serialVersionUID = 1L;

            {
                addTestCase("T123456789 0 987654321 0", ScpTimestampCommandDetails.class);
                addTestCase("C0644 12345 file", ScpReceiveFileCommandDetails.class);
                addTestCase("D0755 0 dir", ScpReceiveDirCommandDetails.class);
                addTestCase(ScpDirEndCommandDetails.HEADER, ScpDirEndCommandDetails.class);
            }

            private void addTestCase(String header, Class<? extends AbstractScpCommandDetails> cmdClass) {
                add(new Object[] { header, cmdClass });
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "cmd={0}")
    public void headerEquality(String header, Class<C> cmdClass) throws Exception {
        initAbstractScpCommandDetailsTest(header, cmdClass);
        C details = ctor.newInstance(header);
        assertEquals(header, details.toHeader());
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "cmd={0}")
    public void detailsEquality(String header, Class<C> cmdClass) throws Exception {
        initAbstractScpCommandDetailsTest(header, cmdClass);
        C d1 = ctor.newInstance(header);
        C d2 = ctor.newInstance(header);
        assertEquals(d1.hashCode(), d2.hashCode(), "HASH ?");
        assertEquals(d1, d2, "EQ ?");
    }
}
