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

package org.apache.sshd.server.shell;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.BaseTestSupport;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TtyFilterInputStreamTest extends BaseTestSupport {
    public TtyFilterInputStreamTest() {
        super();
    }

    @Test
    public void testLfOnlyStream() throws IOException {
        List<String> expected = createTestLines();
        List<String> actual = new ArrayList<>(expected.size());
        byte[] data = GenericUtils.join(expected, "\r\n").getBytes(StandardCharsets.UTF_8);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             TtyFilterInputStream tty = new TtyFilterInputStream(bais, Collections.singleton(TtyOptions.LfOnlyInput)) {
                 private long offset;

                 @Override
                 public synchronized int read() throws IOException {
                     int c = super.read();
                     if (c == -1) {
                         return -1;
                     }

                     offset++;
                     if (c == '\n') {
                         offset++;  // compensate for CR filtering
                     }
                     assertFalse("Unexpected CR at offset=" + offset, c == '\r');
                     return c;
                 }
             };
             BufferedReader rdr = new BufferedReader(new InputStreamReader(tty, StandardCharsets.UTF_8))) {

            for (String line = rdr.readLine(); line != null; line = rdr.readLine()) {
                actual.add(line);
            }
        }

        assertListEquals("Mismatched lines", expected, actual);
    }

    @Test
    public void testCrLfStream() throws IOException {
        List<String> expected = createTestLines();
        List<String> actual = new ArrayList<>(expected.size());
        byte[] data = GenericUtils.join(expected, '\n').getBytes(StandardCharsets.UTF_8);
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             TtyFilterInputStream tty = new TtyFilterInputStream(bais, Collections.singleton(TtyOptions.CrLfInput)) {
                 private long offset;
                 private int lastChar = -1;

                 @Override
                 public synchronized int read() throws IOException {
                     int c = super.read();
                     if (c == -1) {
                         return -1;
                     }

                     if (c != '\r') {
                         offset++;
                     }

                     if (c == '\n') {
                         assertEquals("LF not preceded by CR at offset=" + offset, '\r', lastChar);
                     }

                     lastChar = c;
                     return c;
                 }
             };
             BufferedReader rdr = new BufferedReader(new InputStreamReader(tty, StandardCharsets.UTF_8))) {

            for (String line = rdr.readLine(); line != null; line = rdr.readLine()) {
                actual.add(line);
            }
        }

        assertListEquals("Mismatched lines", expected, actual);
    }

    private List<String> createTestLines() {
        return Arrays.asList(getClass().getPackage().getName(), getClass().getSimpleName(), getCurrentTestName(), new Date(System.currentTimeMillis()).toString());
    }
}
