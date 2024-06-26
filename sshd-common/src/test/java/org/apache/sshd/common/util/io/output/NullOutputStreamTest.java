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

package org.apache.sshd.common.util.io.output;

import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;

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
public class NullOutputStreamTest extends JUnitTestSupport {
    public NullOutputStreamTest() {
        super();
    }

    @Test
    public void testNoAccessAllowedAfterClose() throws IOException {
        NullOutputStream stream = new NullOutputStream();
        stream.close();
        assertFalse("Stream not marked as closed", stream.isOpen());
        assertThrows("Unexpected single value write success", EOFException.class, () -> stream.write('a'));

        byte[] buf = new byte[Byte.SIZE];
        Arrays.fill(buf, (byte) 0x41);
        assertThrows("Unexpected full buffer write success", EOFException.class, () -> stream.write(buf));

        Arrays.fill(buf, (byte) 0x42);
        assertThrows("Unexpected full buffer write success", EOFException.class,
                () -> stream.write(buf, buf.length / 2, (buf.length / 2) - 1));

        assertThrows("Unexpected flush success", EOFException.class, stream::flush);
    }
}
