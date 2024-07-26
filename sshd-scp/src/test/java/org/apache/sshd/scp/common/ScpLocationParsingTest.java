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

import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.Assumptions;
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
public class ScpLocationParsingTest extends JUnitTestSupport {
    private String value;
    private ScpLocation location;

    public void initScpLocationParsingTest(String value, ScpLocation location) {
        this.value = value;
        this.location = location;
    }

    public static List<Object[]> parameters() {
        return new ArrayList<Object[]>() {
            // not serializing it
            private static final long serialVersionUID = 1L;

            {
                addTestCase(null, null);
                addTestCase("", null);
                addTestCase("/local/path/value", new ScpLocation(null, null, "/local/path/value"));
                addTestCase("user@host:/remote/path/value", new ScpLocation("user", "host", "/remote/path/value"));
                addTestCase("scp://user@host/remote/path/value", new ScpLocation("user", "host", "/remote/path/value"));
                addTestCase("scp://user@host:22/remote/path/value", new ScpLocation("user", "host", "/remote/path/value"));
                addTestCase("scp://user@host:2222/remote/path/value",
                        new ScpLocation("user", "host", 2222, "/remote/path/value"));
            }

            private void addTestCase(String value, ScpLocation expected) {
                add(new Object[] { value, expected });
            }
        };
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "value={0}")
    public void locationParsing(String value, ScpLocation location) {
        initScpLocationParsingTest(value, location);
        ScpLocation actual = ScpLocation.parse(value);
        assertEquals(location, actual);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "value={0}")
    public void locationToString(String value, ScpLocation location) {
        initScpLocationParsingTest(value, location);
        Assumptions.assumeTrue(location != null, "No expected value to compate");
        Assumptions.assumeTrue(location.isLocal() || (location.resolvePort() != SshConstants.DEFAULT_PORT),
                "Default port being used");
        String spec = location.toString();
        assertEquals(value, spec);
    }
}
