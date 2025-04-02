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
package org.apache.sshd.common.session.filters;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.sshd.common.filter.InputHandler;
import org.apache.sshd.common.filter.IoFilter;
import org.apache.sshd.common.filter.OutputHandler;
import org.apache.sshd.common.io.DefaultIoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.util.test.JUnitTestSupport;

abstract class FilterTestSupport extends JUnitTestSupport {

    protected static Buffer buf(String data) {
        byte[] raw = data.getBytes(StandardCharsets.US_ASCII);
        return new ByteArrayBuffer(raw);
    }

    protected static String str(Buffer data) {
        byte[] raw = data.array();
        int curr = data.rpos();
        int length = data.available();
        return new String(raw, curr, length, StandardCharsets.US_ASCII);
    }

    protected static class IoWriteFutureWithData extends DefaultIoWriteFuture {

        final Buffer data;

        public IoWriteFutureWithData(Object id, Object lock, Buffer data) {
            super(id, lock);
            this.data = data;
        }

    }

    protected static class OutgoingSink extends IoFilter {

        boolean autoFulfill;

        List<IoWriteFutureWithData> outputs = new ArrayList<>();

        @Override
        public InputHandler in() {
            return owner()::passOn;
        }

        @Override
        public OutputHandler out() {
            return (cmd, buf) -> {
                IoWriteFutureWithData result = new IoWriteFutureWithData(this, null,
                        ByteArrayBuffer.getCompactClone(buf.array(), buf.rpos(), buf.available()));
                outputs.add(result);
                if (autoFulfill) {
                    result.setValue(Boolean.TRUE);
                }
                return result;
            };
        }

    }

    protected static class IncomingSink extends IoFilter {

        List<Buffer> buffers = new ArrayList<>();

        @Override
        public InputHandler in() {
            return buf -> {
                Buffer copy = new ByteArrayBuffer();
                copy.putBuffer(buf);
                buffers.add(copy);
            };
        }

        @Override
        public OutputHandler out() {
            return owner()::send;
        }

    }

}
