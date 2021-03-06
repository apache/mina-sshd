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

package org.apache.sshd.contrib.common.util.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.JUnit4ClassRunnerWithParametersFactory;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.apache.sshd.util.test.NoIoTestCase;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized.UseParametersRunnerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(Parameterized.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@UseParametersRunnerFactory(JUnit4ClassRunnerWithParametersFactory.class)
@Category({ NoIoTestCase.class })
public class LineOutputStreamTest extends JUnitTestSupport {
    private final boolean withCR;

    public LineOutputStreamTest(boolean withCR) {
        this.withCR = withCR;
    }

    @Parameters(name = "CR={0}")
    public static List<Object[]> parameters() {
        return Arrays.asList(new Object[] { Boolean.TRUE }, new Object[] { Boolean.FALSE });
    }

    @Test
    public void testLineParsing() throws IOException {
        List<String> expected = new ArrayList<>();
        String prefix = getClass().getName() + "#" + getCurrentTestName() + "-";
        for (int index = 1; index < Byte.MAX_VALUE; index++) {
            expected.add(prefix + index);
        }

        Path targetFile = getTargetRelativeFile(
                getClass().getSimpleName(), getCurrentTestName() + "-" + (withCR ? "CR" : "LF") + ".txt");
        Files.createDirectories(targetFile.getParent());
        try (OutputStream fout = Files.newOutputStream(targetFile)) {
            int lineCount = 0;
            for (String l : expected) {
                byte[] b = l.getBytes(StandardCharsets.UTF_8);
                fout.write(b);
                if (withCR) {
                    fout.write(0x0d);
                }
                fout.write(0x0a);

                lineCount++;
                if ((lineCount & 0x03) == 0) {
                    if (withCR) {
                        fout.write(0x0d);
                    }
                    fout.write(0x0a);
                }
            }
        }

        List<String> actual = new ArrayList<>(expected.size());
        try (InputStream fin = Files.newInputStream(targetFile);
             OutputStream lout = new LineOutputStream() {
                 private int lineCount;

                 @Override
                 protected void handleLine(byte[] buf, int offset, int len) throws IOException {
                     lineCount++;
                     if (len == 0) {
                         return; // ignore empty lines
                     }

                     byte lastChar = buf[offset + len - 1];
                     if ((lastChar == 0x0a) || (lastChar == 0x0d)) {
                         throw new StreamCorruptedException("Invalid line ending at line #" + lineCount);
                     }

                     String l = new String(buf, offset, len, StandardCharsets.UTF_8);
                     actual.add(l);
                 }
             }) {
            IoUtils.copy(fin, lout);
        }

        assertListEquals(getCurrentTestName(), expected, actual);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[withCR=" + withCR + "]";
    }
}
