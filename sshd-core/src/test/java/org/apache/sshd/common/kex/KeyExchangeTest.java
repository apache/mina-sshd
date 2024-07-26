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

import java.util.Map;
import java.util.function.Function;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class KeyExchangeTest extends BaseTestSupport {
    public KeyExchangeTest() {
        super();
    }

    @Test
    void simpleKexOpcodeName() {
        testKexOpcodeName(KeyExchange.SIMPLE_KEX_OPCODES_MAP, KeyExchange::getSimpleKexOpcodeName);
    }

    @Test
    void groupKexOpcodeName() {
        testKexOpcodeName(KeyExchange.GROUP_KEX_OPCODES_MAP, KeyExchange::getGroupKexOpcodeName);
    }

    private static void testKexOpcodeName(Map<Integer, String> opsMap, Function<Integer, String> xformer) {
        opsMap.forEach((cmd, expected) -> {
            String actual = xformer.apply(cmd);
            assertSame(expected, actual, "Mismatched results for cmd=" + cmd);

            if (SshConstants.isAmbiguousOpcode(cmd)) {
                assertEquals(cmd.toString(),
                        SshConstants.getCommandMessageName(cmd),
                        "Unexpected ambiguous command resolution for " + cmd);
            }
        });
    }
}
