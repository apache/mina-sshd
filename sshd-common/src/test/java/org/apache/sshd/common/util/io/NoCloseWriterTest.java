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

package org.apache.sshd.common.util.io;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;

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
public class NoCloseWriterTest extends JUnitTestSupport {
    public NoCloseWriterTest() {
        super();
    }

    @Test
    public void testCanKeepWritingAfterClose() throws IOException {
        Path dir = createTempClassFolder();
        Path file = dir.resolve(getCurrentTestName() + ".txt");
        Files.deleteIfExists(file);

        String expected = getClass().getName() + "#" + getCurrentTestName() + "@" + new Date();
        try (OutputStream fileStream = Files.newOutputStream(file);
             Writer w = new OutputStreamWriter(fileStream, StandardCharsets.UTF_8);
             Writer shielded = new NoCloseWriter(w)) {
            int index = 0;
            int availLen = expected.length();
            for (; index < (availLen / 2); index++) {
                shielded.close();
                shielded.write(expected.charAt(index));
            }

            w.write(expected, index, availLen - index);
        }

        byte[] actualBytes = Files.readAllBytes(file);
        String actual = new String(actualBytes, StandardCharsets.UTF_8);
        assertEquals(expected, actual);
    }

}
