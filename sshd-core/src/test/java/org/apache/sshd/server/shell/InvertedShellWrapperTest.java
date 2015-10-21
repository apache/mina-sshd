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
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.sshd.util.test.BaseTestSupport;
import org.apache.sshd.util.test.BogusEnvironment;
import org.apache.sshd.util.test.BogusExitCallback;
import org.apache.sshd.util.test.BogusInvertedShell;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class InvertedShellWrapperTest extends BaseTestSupport {
    public InvertedShellWrapperTest() {
        super();
    }

    @Test
    public void testStreamsAreFlushedBeforeClosing() throws Exception {
        BogusInvertedShell shell = newShell("out", "err");
        shell.setAlive(false);

        try (ByteArrayInputStream in = new ByteArrayInputStream("in".getBytes(StandardCharsets.UTF_8));
             ByteArrayOutputStream out = new ByteArrayOutputStream(50);
             ByteArrayOutputStream err = new ByteArrayOutputStream()) {

            InvertedShellWrapper wrapper = new InvertedShellWrapper(shell);
            try {
                wrapper.setInputStream(in);
                wrapper.setOutputStream(out);
                wrapper.setErrorStream(err);
                wrapper.setExitCallback(new BogusExitCallback());
                wrapper.start(new BogusEnvironment());

                wrapper.pumpStreams();

                // check the streams were flushed before exiting
                assertEquals("stdin", "in", shell.getInputStream().toString());
                assertEquals("stdout", "out", out.toString());
                assertEquals("stderr", "err", err.toString());
            } finally {
                wrapper.destroy();
            }
        }
    }

    @Test   // see SSHD-570
    public void testExceptionWhilePumpStreams() throws Exception {
        final BogusInvertedShell bogusShell = newShell("out", "err");
        bogusShell.setAlive(false);

        final int DESTROYED_EXIT_VALUE = 7365;
        InvertedShell shell = new InvertedShell() {
            private boolean destroyed;

            @Override
            public void start(Map<String, String> env) throws IOException {
                bogusShell.start(env);
            }

            @Override
            public boolean isAlive() {
                return bogusShell.isAlive();
            }

            @Override
            public InputStream getOutputStream() {
                return bogusShell.getOutputStream();
            }

            @Override
            public OutputStream getInputStream() {
                return bogusShell.getInputStream();
            }

            @Override
            public InputStream getErrorStream() {
                return bogusShell.getErrorStream();
            }

            @Override
            public int exitValue() {
                return destroyed ? DESTROYED_EXIT_VALUE : bogusShell.exitValue();
            }

            @Override
            public void destroy() {
                bogusShell.destroy();
                bogusShell.setAlive(false);
                destroyed = true;
            }
        };

        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayOutputStream err = new ByteArrayOutputStream();
             InputStream stdin = new InputStream() {
                private final byte[] data = getCurrentTestName().getBytes(StandardCharsets.UTF_8);
                private int readPos;

                @Override
                public int read() throws IOException {
                    if (readPos >= data.length) {
                        throw new EOFException("Data exhausted");
                    }

                    return data[readPos++];
                }

                @Override
                public int available() throws IOException {
                    return data.length;
                }
             }) {

            BogusExitCallback exitCallback = new BogusExitCallback();
            InvertedShellWrapper wrapper = new InvertedShellWrapper(shell);
            try {
                wrapper.setInputStream(stdin);
                wrapper.setOutputStream(out);
                wrapper.setErrorStream(err);

                wrapper.setExitCallback(exitCallback);
                wrapper.start(new BogusEnvironment());

                wrapper.pumpStreams();
            } finally {
                wrapper.destroy();
            }

            assertEquals("Mismatched exit value", DESTROYED_EXIT_VALUE, exitCallback.getExitValue());
            assertEquals("Mismatched exit message", EOFException.class.getSimpleName(), exitCallback.getExitMessage());
        }
    }

    private BogusInvertedShell newShell(String contentOut, String contentErr) {
        ByteArrayOutputStream in = new ByteArrayOutputStream(20);
        ByteArrayInputStream out = new ByteArrayInputStream(contentOut.getBytes(StandardCharsets.UTF_8));
        ByteArrayInputStream err = new ByteArrayInputStream(contentErr.getBytes(StandardCharsets.UTF_8));
        return new BogusInvertedShell(in, out, err);
    }
}
