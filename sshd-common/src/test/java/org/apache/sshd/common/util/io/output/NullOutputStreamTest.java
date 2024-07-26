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
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class)
@Tag("NoIoTestCase")
public class NullOutputStreamTest extends JUnitTestSupport {
    public NullOutputStreamTest() {
        super();
    }

    @Test
    void noAccessAllowedAfterClose() throws IOException {
        NullOutputStream stream = new NullOutputStream();
        stream.close();
        assertFalse(stream.isOpen(), "Stream not marked as closed");
        assertThrows(EOFException.class, () -> stream.write('a'), "Unexpected single value write success");

        byte[] buf = new byte[Byte.SIZE];
        Arrays.fill(buf, (byte) 0x41);
        assertThrows(EOFException.class, () -> stream.write(buf), "Unexpected full buffer write success");

        Arrays.fill(buf, (byte) 0x42);
        assertThrows(EOFException.class,
                () -> stream.write(buf, buf.length / 2, (buf.length / 2) - 1),
                "Unexpected full buffer write success");

        assertThrows(EOFException.class, stream::flush, "Unexpected flush success");
    }
}
