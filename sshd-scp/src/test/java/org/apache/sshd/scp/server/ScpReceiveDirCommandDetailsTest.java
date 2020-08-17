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
public class ScpReceiveDirCommandDetailsTest extends JUnitTestSupport {
    public ScpReceiveDirCommandDetailsTest() {
        super();
    }

    @Test
    public void testLengthDoesNotInfluenceEquality() {
        ScpReceiveDirCommandDetails d1 = new ScpReceiveDirCommandDetails("D0555 0 " + getCurrentTestName());
        ScpReceiveDirCommandDetails d2 = new ScpReceiveDirCommandDetails(d1.toHeader());
        d2.setLength(d1.getLength() + 1234L);
        assertNotEquals("Len ?", d1.getLength(), d2.getLength());
        assertEquals("Hash ?", d1.hashCode(), d2.hashCode());
        assertEquals("EQ", d1, d2);
    }
}
