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

package org.apache.sshd.common.kex;

import java.util.Arrays;

import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.fail;

@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class AbstractDHTest extends BaseTestSupport {
    public AbstractDHTest() {
        super();
    }

    @Test
    void stripLeadingZeroes() {
        byte[] data = { 3, 7, 7, 3, 4, 7 };
        for (int index = 1; index <= data.length; index++) {
            assertSame(data,
                    AbstractDH.stripLeadingZeroes(data),
                    "Unexpected sub-array generation for " + Arrays.toString(data));
            if (index < data.length) {
                data[index] = 0;
            }
        }

        Arrays.fill(data, (byte) 0);
        try {
            byte[] stripped = AbstractDH.stripLeadingZeroes(data);
            fail("Unexpected success for all zeroes data: " + Arrays.toString(stripped));
        } catch (IllegalArgumentException expected) {
            // ignored
        }

        for (int index = data.length - 1; index > 0; index--) {
            data[index] = (byte) index;

            byte[] stripped = AbstractDH.stripLeadingZeroes(data);
            String ds = Arrays.toString(data);
            String ss = Arrays.toString(stripped);
            assertEquals(data.length - index, stripped.length, "Mismatched stripped (" + ss + ") length for " + ds);
            for (int i = index, j = 0; j < stripped.length; i++, j++) {
                if (data[i] != stripped[j]) {
                    fail("Mismatched values at stripped index = " + j + ": data=" + ds + ", stripped=" + ss);
                }
            }
        }
    }
}
