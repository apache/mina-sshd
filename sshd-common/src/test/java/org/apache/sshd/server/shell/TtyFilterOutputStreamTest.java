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

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class TtyFilterOutputStreamTest extends JUnitTestSupport {
    private PtyMode mode;

    public TtyFilterOutputStreamTest() {
    }

    public void initTtyFilterOutputStreamTest(PtyMode mode) {
        this.mode = Objects.requireNonNull(mode, "No test modes");
    }

    public static Collection<Object[]> parameters() {
        return parameterize(TtyFilterOutputStream.OUTPUT_OPTIONS);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "mode={0}")
    public void crlfHandling(PtyMode mode) throws IOException {
        initTtyFilterOutputStreamTest(mode);
        List<String> lines = Arrays.asList(getClass().getPackage().getName(),
                getClass().getSimpleName(), getCurrentTestName(),
                "(" + mode + ")", new Date(System.currentTimeMillis()).toString());

        AtomicInteger crCount = new AtomicInteger(0);
        AtomicInteger lfCount = new AtomicInteger(0);
        try (OutputStream output = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                if (b == '\r') {
                    crCount.incrementAndGet();
                } else if (b == '\n') {
                    lfCount.incrementAndGet();
                }
            }
        };
             TtyFilterOutputStream ttyOut = new TtyFilterOutputStream(
                     output, null, PtyMode.ECHO.equals(mode) ? Collections.emptySet() : EnumSet.of(mode));
             Writer writer = new OutputStreamWriter(ttyOut, StandardCharsets.UTF_8)) {

            for (String l : lines) {
                writer.append(l).append("\r\n");
            }
        }

        assertCRLFCounts(mode, lines.size() /* we add a NL after each line */, crCount.get(), lfCount.get());
    }

    private static void assertCRLFCounts(PtyMode mode, int numLines, int crCount, int lfCount) {
        switch (mode) {
            case ECHO: // no modifications
                assertEquals(numLines, crCount, "Mismatched CR coumt");
                assertEquals(numLines, lfCount, "Mismatched LF coumt");
                break;

            case INLCR: // Map NL into CR
                assertEquals(numLines * 2, crCount, "Mismatched CR count");
                assertEquals(0, lfCount, "Mismatched LF coumt");
                break;

            case ICRNL: // Map CR to NL on input
                assertEquals(0, crCount, "Mismatched CR count");
                assertEquals(numLines * 2, lfCount, "Mismatched LF coumt");
                break;

            case IGNCR: // Ignore CR
                assertEquals(0, crCount, "Mismatched CR count");
                assertEquals(numLines, lfCount, "Mismatched LF coumt");
                break;

            default:
                fail("Unsupported mode: " + mode);
        }
    }
}
