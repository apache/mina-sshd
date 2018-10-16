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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
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
public class NoCloseReaderTest extends JUnitTestSupport {
    public NoCloseReaderTest() {
        super();
    }

    @Test
    public void testCanKeepReadingAfterClose() throws IOException {
        String expected = getClass().getName() + "#" + getCurrentTestName() + "@" + new Date();
        Path dir = createTempClassFolder();
        Path file = Files.write(dir.resolve(getCurrentTestName() + ".txt"), expected.getBytes(StandardCharsets.UTF_8));
        try (InputStream fileStream = Files.newInputStream(file);
             Reader rdr = new InputStreamReader(fileStream, StandardCharsets.UTF_8);
             Reader shielded = new NoCloseReader(rdr)) {
            int index = 0;

            int availLen = expected.length();
            for (; index < (availLen / 2); index++) {
                shielded.close();

                int readValue = shielded.read();
                if (readValue == -1) {
                    fail("Premature EOF after shield read of " + index + " bytes");
                }

                char expValue = expected.charAt(index);
                char actValue = (char) (readValue & 0xFFFF);
                if (expValue != actValue) {
                    fail("Mismatched shielded read value after " + index + " bytes");
                }
            }

            for (; index < availLen; index++) {
                int readValue = rdr.read();
                if (readValue == -1) {
                    fail("Premature EOF after original read of " + index + " bytes");
                }

                char expValue = expected.charAt(index);
                char actValue = (char) (readValue & 0xFFFF);
                if (expValue != actValue) {
                    fail("Mismatched original read value after " + index + " bytes");
                }
            }

            int readValue = shielded.read();
            assertEquals("Shielded EOF not signalled", -1, readValue);

            readValue = rdr.read();
            assertEquals("Original EOF not signalled", -1, readValue);
        }
    }

}
