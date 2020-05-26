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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.common.channel.PtyMode;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
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
public class TtyFilterInputStreamTest extends JUnitTestSupport {
    private static final List<PtyMode> MODES = Collections.unmodifiableList(
            Stream.concat(Stream.of(PtyMode.ECHO), TtyFilterInputStream.INPUT_OPTIONS.stream())
                    .collect(Collectors.toList()));

    private final PtyMode mode;

    public TtyFilterInputStreamTest(PtyMode mode) {
        this.mode = Objects.requireNonNull(mode, "No test modes");
    }

    @Parameters(name = "mode={0}")
    public static Collection<Object[]> parameters() {
        return parameterize(MODES);
    }

    @Test
    public void testCRLFHandling() throws IOException {
        List<String> lines = Arrays.asList(getClass().getPackage().getName(),
                getClass().getSimpleName(), getCurrentTestName(),
                "(" + mode + ")", new Date(System.currentTimeMillis()).toString());
        String content = GenericUtils.join(lines, "\r\n");
        try (ByteArrayInputStream bais = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
             TtyFilterInputStream tty = new TtyFilterInputStream(bais, EnumSet.of(mode))) {
            final AtomicInteger crCount = new AtomicInteger(0);
            final AtomicInteger lfCount = new AtomicInteger(0);

            try (OutputStream output = new OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    if (b == '\r') {
                        crCount.incrementAndGet();
                    } else if (b == '\n') {
                        lfCount.incrementAndGet();
                    }
                }
            }) {
                long copySize = IoUtils.copy(tty, output);
                assertTrue("Copy size (" + copySize + ") above total length (" + content.length() + ")",
                        copySize <= content.length());
            }

            assertCRLFCounts(mode, lines.size() - 1 /* last line has no NL */, crCount.get(), lfCount.get());
        }
    }

    @Test
    public void testInternalBufferSizeDoesNotGrow() throws Exception {
        try (TtyFilterInputStream is = new TtyFilterInputStream(new InputStream() {
            int next;

            @Override
            public int read() {
                next = (next + 1) & 0xFF;
                return next;
            }
        }, EnumSet.of(mode))) {
            Field f = is.getClass().getDeclaredField("buffer");
            f.setAccessible(true);
            ByteArrayBuffer buffer = (ByteArrayBuffer) f.get(is);

            byte[] b = new byte[256];
            for (int i = 0; i < 10; i++) {
                is.read(b, 0, b.length);
            }

            int size = buffer.capacity();

            for (int i = 0; i < 10; i++) {
                is.read(b, 0, b.length);
            }
            assertEquals(size, buffer.capacity());
        }
    }

    private static void assertCRLFCounts(PtyMode mode, int numLines, int crCount, int lfCount) {
        switch (mode) {
            case ECHO:
            case ONLCR:
            case ONOCR:
                // No modifications
                assertEquals("Mismatched CR count", numLines, crCount);
                assertEquals("Mismatched LF count", numLines, lfCount);
                break;

            case OCRNL:
                // Translate carriage return to newline
                assertEquals("Mismatched CR count", 0, crCount);
                assertEquals("Mismatched LF count", 2 * numLines, lfCount);
                break;

            case ONLRET:
                // Newline performs a carriage return
                assertEquals("Mismatched CR count", 2 * numLines, crCount);
                assertEquals("Mismatched LF count", 0, lfCount);
                break;

            default:
                fail("Unsupported mode: " + mode);
        }
    }
}
