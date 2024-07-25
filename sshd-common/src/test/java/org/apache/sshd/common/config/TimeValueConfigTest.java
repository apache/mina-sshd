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

package org.apache.sshd.common.config;

import java.util.concurrent.TimeUnit;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class TimeValueConfigTest extends JUnitTestSupport {
    public TimeValueConfigTest() {
        super();
    }

    @Test
    void durationOf() {
        Object[] values = {
                "600", TimeUnit.SECONDS.toMillis(600L),
                "10m", TimeUnit.MINUTES.toMillis(10L),
                "1h30m", TimeUnit.MINUTES.toMillis(90L),
                "2d", TimeUnit.DAYS.toMillis(2L),
                "3w", TimeUnit.DAYS.toMillis(3L * 7L)
        };
        for (int index = 0; index < values.length; index += 2) {
            String s = (String) values[index];
            Number expected = (Number) values[index + 1];
            long actual = TimeValueConfig.durationOf(s);
            assertEquals(expected.longValue(), actual, s);
        }
    }
}
