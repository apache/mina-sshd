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
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
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
public class TtyFilterOutputStreamTest extends BaseTestSupport {
    public TtyFilterOutputStreamTest() {
        super();
    }

    @Test
    public void testNoEchoIfNotInTtyOptions() throws IOException {
        try (TtyFilterInputStream ttyIn = new TtyFilterInputStream(new ByteArrayInputStream(GenericUtils.EMPTY_BYTE_ARRAY), Collections.<TtyOptions>emptySet());
             ByteArrayOutputStream baos = new ByteArrayOutputStream(Byte.MAX_VALUE);
             TtyFilterOutputStream ttyOut = new TtyFilterOutputStream(baos, ttyIn, Collections.<TtyOptions>emptySet())) {

            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(ttyOut, StandardCharsets.UTF_8))) {
                writer.append(getClass().getName()).append('#').append(getCurrentTestName());
                writer.newLine();
            }

            assertEquals("Unexpected data echoed", 0, ttyIn.available());
        }
    }

    @Test
    public void testLfOnlyOutput() throws IOException {
        List<String> expected = createTestLines();
        byte[] data = GenericUtils.join(expected, "\r\n").getBytes(StandardCharsets.UTF_8);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length)) {
            try (TtyFilterOutputStream ttyOut = new TtyFilterOutputStream(baos, null, EnumSet.of(TtyOptions.LfOnlyOutput)) {
                     private long offset;

                     @Override
                     protected void writeRawOutput(int c) throws IOException {
                         offset++;
                         if (c == '\n') {
                             offset++;  // compensate for CR filtering
                         }
                         assertNotEquals("Unexpected CR at offset=" + offset, '\r', c);
                         super.writeRawOutput(c);
                     }
             }) {
                ttyOut.write(data);
            }

            List<String> actual = new ArrayList<>(expected.size());
            try (BufferedReader rdr = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(baos.toByteArray()), StandardCharsets.UTF_8))) {
               for (String line = rdr.readLine(); line != null; line = rdr.readLine()) {
                   actual.add(line);
               }
            }

            assertListEquals("Mismatched read lines", expected, actual);
        }
    }

    @Test
    public void testCrLfOutput() throws IOException {
        List<String> expected = createTestLines();
        byte[] data = GenericUtils.join(expected, '\n').getBytes(StandardCharsets.UTF_8);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length)) {
            try (TtyFilterOutputStream ttyOut = new TtyFilterOutputStream(baos, null, EnumSet.of(TtyOptions.CrLfOutput)) {
                     private long offset;
                     private int lastChar = -1;

                     @Override
                     protected void writeRawOutput(int c) throws IOException {
                         if (c != '\r') {
                             offset++;  // compensate for CR insertion
                         }

                         if (c == '\n') {
                             assertEquals("No CR at offset=" + offset, '\r', lastChar);
                         }

                         super.writeRawOutput(c);
                         lastChar = c;
                     }
             }) {
                ttyOut.write(data);
            }

            List<String> actual = new ArrayList<>(expected.size());
            try (BufferedReader rdr = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(baos.toByteArray()), StandardCharsets.UTF_8))) {
               for (String line = rdr.readLine(); line != null; line = rdr.readLine()) {
                   actual.add(line);
               }
            }

            assertListEquals("Mismatched read lines", expected, actual);
        }
    }

    private List<String> createTestLines() {
        return Arrays.asList(getClass().getPackage().getName(), getClass().getSimpleName(), getCurrentTestName(), new Date(System.currentTimeMillis()).toString());
    }

}
