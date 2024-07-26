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

package org.apache.sshd.scp.server;

import org.apache.sshd.scp.common.helpers.ScpReceiveDirCommandDetails;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class ScpReceiveDirCommandDetailsTest extends JUnitTestSupport {
    public ScpReceiveDirCommandDetailsTest() {
        super();
    }

    @Test
    void lengthDoesNotInfluenceEquality() {
        ScpReceiveDirCommandDetails d1 = new ScpReceiveDirCommandDetails("D0555 0 " + getCurrentTestName());
        ScpReceiveDirCommandDetails d2 = new ScpReceiveDirCommandDetails(d1.toHeader());
        d2.setLength(d1.getLength() + 1234L);
        assertNotEquals(d1.getLength(), d2.getLength(), "Len ?");
        assertEquals(d1.hashCode(), d2.hashCode(), "Hash ?");
        assertEquals(d1, d2, "EQ");
    }
}
