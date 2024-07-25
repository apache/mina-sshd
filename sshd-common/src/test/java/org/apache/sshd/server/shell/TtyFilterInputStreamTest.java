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
import org.apache.sshd.util.test.JUnitTestSupport;
import org.junit.jupiter.api.MethodOrderer.MethodName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@TestMethodOrder(MethodName.class) // see https://github.com/junit-team/junit/wiki/Parameterized-tests
@Tag("NoIoTestCase")
public class TtyFilterInputStreamTest extends JUnitTestSupport {
    private static final List<PtyMode> MODES = Collections.unmodifiableList(
            Stream.concat(Stream.of(PtyMode.ECHO), TtyFilterInputStream.INPUT_OPTIONS.stream())
                    .collect(Collectors.toList()));

    private PtyMode mode;

    public TtyFilterInputStreamTest() {
    }

    public void initTtyFilterInputStreamTest(PtyMode mode) {
        this.mode = Objects.requireNonNull(mode, "No test modes");
    }

    public static Collection<Object[]> parameters() {
        return parameterize(MODES);
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "mode={0}")
    public void crlfHandling(PtyMode mode) throws IOException {
        initTtyFilterInputStreamTest(mode);
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
                assertTrue(copySize <= content.length(),
                        "Copy size (" + copySize + ") above total length (" + content.length() + ")");
            }

            assertCRLFCounts(mode, lines.size() - 1 /* last line has no NL */, crCount.get(), lfCount.get());
        }
    }

    @MethodSource("parameters")
    @ParameterizedTest(name = "mode={0}")
    public void internalBufferSizeDoesNotGrow(PtyMode mode) throws Exception {
        initTtyFilterInputStreamTest(mode);
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
                assertEquals(numLines, crCount, "Mismatched CR count");
                assertEquals(numLines, lfCount, "Mismatched LF count");
                break;

            case OCRNL:
                // Translate carriage return to newline
                assertEquals(0, crCount, "Mismatched CR count");
                assertEquals(2 * numLines, lfCount, "Mismatched LF count");
                break;

            case ONLRET:
                // Newline performs a carriage return
                assertEquals(2 * numLines, crCount, "Mismatched CR count");
                assertEquals(0, lfCount, "Mismatched LF count");
                break;

            default:
                fail("Unsupported mode: " + mode);
        }
    }
}
