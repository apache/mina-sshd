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
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@Category({ NoIoTestCase.class })
public class KeyExchangeTest extends BaseTestSupport {
    public KeyExchangeTest() {
        super();
    }

    @Test
    public void testSimpleKexOpcodeName() {
        testKexOpcodeName(KeyExchange.SIMPLE_KEX_OPCODES_MAP, KeyExchange::getSimpleKexOpcodeName);
    }

    @Test
    public void testGroupKexOpcodeName() {
        testKexOpcodeName(KeyExchange.GROUP_KEX_OPCODES_MAP, KeyExchange::getGroupKexOpcodeName);
    }

    private static void testKexOpcodeName(Map<Integer, String> opsMap, Function<Integer, String> xformer) {
        opsMap.forEach((cmd, expected) -> {
            String actual = xformer.apply(cmd);
            assertSame("Mismatched results for cmd=" + cmd, expected, actual);

            if (SshConstants.isAmbiguousOpcode(cmd)) {
                assertEquals("Unexpected ambiguous command resolution for " + cmd, cmd.toString(),
                        SshConstants.getCommandMessageName(cmd));
            }
        });
    }
}
