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
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.Assume;
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
public class ScpLocationParsingTest extends JUnitTestSupport {
    private final String value;
    private final ScpLocation location;

    public ScpLocationParsingTest(String value, ScpLocation location) {
        this.value = value;
        this.location = location;
    }

    @Parameters(name = "value={0}")
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

    @Test
    public void testLocationParsing() {
        ScpLocation actual = ScpLocation.parse(value);
        assertEquals(location, actual);
    }

    @Test
    public void testLocationToString() {
        Assume.assumeTrue("No expected value to compate", location != null);
        Assume.assumeTrue("Default port being used",
                location.isLocal() || (location.resolvePort() != SshConstants.DEFAULT_PORT));
        String spec = location.toString();
        assertEquals(value, spec);
    }
}
