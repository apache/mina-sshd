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

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TimeValueConfigTest extends BaseTestSupport {
    public TimeValueConfigTest() {
        super();
    }

    @Test
    public void testDurationOf() {
        Object[] values = {
            "600", Long.valueOf(TimeUnit.SECONDS.toMillis(600L)),
            "10m", Long.valueOf(TimeUnit.MINUTES.toMillis(10L)),
            "1h30m", Long.valueOf(TimeUnit.MINUTES.toMillis(90L)),
            "2d", Long.valueOf(TimeUnit.DAYS.toMillis(2L)),
            "3w", Long.valueOf(TimeUnit.DAYS.toMillis(3L * 7L))
        };
        for (int index = 0; index < values.length; index += 2) {
            String s = (String) values[index];
            Number expected = (Number) values[index + 1];
            long actual = TimeValueConfig.durationOf(s);
            assertEquals(s, expected.longValue(), actual);
        }
    }
}
