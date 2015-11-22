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

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.util.Transformer;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class KeyExchangeTest extends BaseTestSupport {
    public KeyExchangeTest() {
        super();
    }

    @Test
    public void testSimpleKexOpcodeName() {
        testKexOpcodeName(KeyExchange.Utils.SIMPLE_KEX_OPCODES_MAP, new Transformer<Integer, String>() {
            @Override
            public String transform(Integer cmd) {
                return KeyExchange.Utils.getSimpleKexOpcodeName(cmd);
            }
        });
    }

    @Test
    public void testGroupKexOpcodeName() {
        testKexOpcodeName(KeyExchange.Utils.GROUP_KEX_OPCODES_MAP, new Transformer<Integer, String>() {
            @Override
            public String transform(Integer cmd) {
                return KeyExchange.Utils.getGroupKexOpcodeName(cmd);
            }
        });
    }

    private static void testKexOpcodeName(Map<Integer, String> opsMap, Transformer<Integer, String> xformer) {
        for (Map.Entry<Integer, String> oe : opsMap.entrySet()) {
            Integer cmd = oe.getKey();
            String expected = oe.getValue();
            String actual = xformer.transform(cmd);
            assertSame("Mismatched results for cmd=" + cmd, expected, actual);

            if (SshConstants.isAmbigouosOpcode(cmd)) {
                assertEquals("Unexpected ambiguous command resolution for " + cmd, cmd.toString(), SshConstants.getCommandMessageName(cmd));
            }
        }
    }
}
