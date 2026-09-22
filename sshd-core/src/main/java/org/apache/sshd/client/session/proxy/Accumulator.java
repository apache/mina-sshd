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
package org.apache.sshd.client.session.proxy;

import java.io.IOException;
import java.util.Arrays;

import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

/**
 * Accumulates bytes until the first occurrence of a given byte sequence.
 */
class Accumulator {

    private final int limit;

    private final byte[] endOfData;

    private final String errorMessage;

    private ByteArrayBuffer buf = new ByteArrayBuffer();

    private int split = -1;

    Accumulator(int limit, byte[] endOfData, String errorMessage) {
        ValidateUtils.checkTrue(endOfData.length > 0, "end marker must be non-empty");
        ValidateUtils.checkTrue(limit >= endOfData.length, "limit must be >= length of end marker");
        this.endOfData = endOfData.clone();
        this.limit = limit;
        this.errorMessage = errorMessage;
    }

    /**
     * Accumulates the given input and returns whether the end marker was found.
     *
     * @param  input       to accumulate
     * @return             {@code true} if the data accumulated so far contains the end marker, {@code false} otherwise
     * @throws IOException if the limit is exceeded
     */
    boolean accumulate(Readable input) throws IOException {
        int lastCheck = buf.available();
        buf.putBuffer(input);
        int len = buf.available();
        if (split < 0 && len > lastCheck && len >= endOfData.length) {
            // Avoid re-checking already checked parts of the buffer. If the last check didn't find the end marker up to
            // lastCheck, we don't have to start over again at the beginning: it suffices to double check the last N-1
            // bytes (plus then the new bytes) if N is endOfData.length.
            int from = (lastCheck >= endOfData.length) ? lastCheck + 1 - endOfData.length : buf.rpos();
            split = indexOf(buf.array(), from, buf.rpos() + len - from, endOfData);
            if (split >= 0) {
                return true;
            }
        }
        if (len > limit) {
            if (split >= 0) {
                throw new IOException("Limit exceeded after marker was found at index " + split + "; limit = " + limit);
            } else {
                throw new IOException("Accumulated too much data (max. " + limit + " bytes): " + errorMessage);
            }
        }
        return split >= 0;
    }

    byte[] getData() {
        if (split < 0) {
            throw new IllegalStateException("Data not yet determined");
        }
        return Arrays.copyOfRange(buf.array(), buf.rpos(), split + endOfData.length);
    }

    byte[] getRest() {
        if (split < 0) {
            throw new IllegalStateException("Data not yet determined, so rest still unknown");
        }
        return Arrays.copyOfRange(buf.array(), split + endOfData.length, buf.wpos());
    }

    void clear() {
        buf = new ByteArrayBuffer();
        split = -1;
    }

    private static int indexOf(byte[] data, int from, int len, byte[] needle) {
        int to = from + len - needle.length;
        for (int i = from; i <= to; i++) {
            int j = 0;
            for (int k = i; j < needle.length && data[k] == needle[j]; k++) {
                j++;
            }
            if (j == needle.length) {
                return i;
            }
        }
        return -1;
    }
}
