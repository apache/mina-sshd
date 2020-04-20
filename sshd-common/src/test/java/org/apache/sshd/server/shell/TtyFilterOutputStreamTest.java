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
public class TtyFilterOutputStreamTest extends JUnitTestSupport {
    private final PtyMode mode;

    public TtyFilterOutputStreamTest(PtyMode mode) {
        this.mode = Objects.requireNonNull(mode, "No test modes");
    }

    @Parameters(name = "mode={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(TtyFilterOutputStream.OUTPUT_OPTIONS);
    }

    @Test
    public void testCRLFHandling() throws IOException {
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
                assertEquals("Mismatched CR coumt", numLines, crCount);
                assertEquals("Mismatched LF coumt", numLines, lfCount);
                break;

            case INLCR: // Map NL into CR
                assertEquals("Mismatched CR count", numLines * 2, crCount);
                assertEquals("Mismatched LF coumt", 0, lfCount);
                break;

            case ICRNL: // Map CR to NL on input
                assertEquals("Mismatched CR count", 0, crCount);
                assertEquals("Mismatched LF coumt", numLines * 2, lfCount);
                break;

            case IGNCR: // Ignore CR
                assertEquals("Mismatched CR count", 0, crCount);
                assertEquals("Mismatched LF coumt", numLines, lfCount);
                break;

            default:
                fail("Unsupported mode: " + mode);
        }
    }
}
