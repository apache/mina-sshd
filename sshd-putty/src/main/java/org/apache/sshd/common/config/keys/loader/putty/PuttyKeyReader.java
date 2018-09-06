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

package org.apache.sshd.common.config.keys.loader.putty;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Helper class for {@code Putty} key files decoders
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PuttyKeyReader implements Closeable {
    private final DataInputStream di;

    public PuttyKeyReader(InputStream s) {
        di = new DataInputStream(s);
    }

    public void skip() throws IOException {
        int skipSize = di.readInt();
        int effectiveSkip = di.skipBytes(skipSize);
        if (skipSize != effectiveSkip) {
            throw new StreamCorruptedException("Mismatched skip size: expected" + skipSize + ", actual=" + effectiveSkip);
        }
    }

    public String readString() throws IOException {
        return readString(StandardCharsets.UTF_8);
    }

    public String readString(Charset cs) throws IOException {
        byte[] data = read();
        return new String(data, cs);
    }

    public BigInteger readInt() throws IOException {
        byte[] bytes = read();
        return new BigInteger(bytes);
    }

    public byte[] read() throws IOException {
        int len = di.readInt();
        byte[] r = new byte[len];
        di.readFully(r);
        return r;
    }

    @Override
    public void close() throws IOException {
        di.close();
    }
}
