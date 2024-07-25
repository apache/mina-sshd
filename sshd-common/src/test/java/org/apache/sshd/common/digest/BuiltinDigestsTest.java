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

package org.apache.sshd.common.digest;

import java.lang.reflect.Field;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class BuiltinDigestsTest extends JUnitTestSupport {
    public BuiltinDigestsTest() {
        super();
    }

    @Test
    void fromName() {
        for (BuiltinDigests expected : BuiltinDigests.VALUES) {
            String name = expected.getName();
            BuiltinDigests actual = BuiltinDigests.fromFactoryName(name);
            assertSame(expected, actual, name);
        }
    }

    @Test
    void allConstantsCovered() throws Exception {
        Set<BuiltinDigests> avail = EnumSet.noneOf(BuiltinDigests.class);
        Field[] fields = BuiltinDigests.Constants.class.getFields();
        for (Field f : fields) {
            String name = (String) f.get(null);
            BuiltinDigests value = BuiltinDigests.fromFactoryName(name);
            assertNotNull(value, "No match found for " + name);
            assertTrue(avail.add(value), name + " re-specified");
        }

        assertEquals("Incomplete coverage", BuiltinDigests.VALUES, avail);
    }
}
