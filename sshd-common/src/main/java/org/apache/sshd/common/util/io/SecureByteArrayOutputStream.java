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

package org.apache.sshd.common.util.io;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * A {@link ByteArrayOutputStream} that clears its internal buffer after resizing and when it is {@link #close()
 * closed}.
 */
public final class SecureByteArrayOutputStream extends ByteArrayOutputStream {

    public SecureByteArrayOutputStream() {
        super();
    }

    public SecureByteArrayOutputStream(int initialSize) {
        super(initialSize);
    }

    @Override
    public void close() {
        Arrays.fill(buf, (byte) 0);
    }

    @Override
    public void write(int b) {
        byte[] oldBuf = buf;
        super.write(b);
        if (buf != oldBuf) {
            Arrays.fill(oldBuf, (byte) 0);
        }
    }

    @Override
    public void write(byte[] b, int off, int len) {
        byte[] oldBuf = buf;
        super.write(b, off, len);
        if (buf != oldBuf) {
            Arrays.fill(oldBuf, (byte) 0);
        }
    }
}
