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
package org.apache.sshd.common.compression;

import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * ZLib based Compression.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CompressionZlib extends BaseCompression {

    private static final int BUF_SIZE = 4096;

    private byte[] tmpbuf = new byte[BUF_SIZE];
    private Deflater compresser;
    private Inflater decompresser;

    /**
     * Create a new instance of a ZLib base compression
     */
    public CompressionZlib() {
        this(BuiltinCompressions.Constants.ZLIB);
    }

    protected CompressionZlib(String name) {
        super(name);
    }

    @Override
    public boolean isDelayed() {
        return false;
    }

    @Override
    public void init(Type type, int level) {
        compresser = new Deflater(level);
        decompresser = new Inflater();
    }

    @Override
    public void compress(Buffer buffer) throws IOException {
        compresser.setInput(buffer.array(), buffer.rpos(), buffer.available());
        buffer.wpos(buffer.rpos());
        for (int len = compresser.deflate(tmpbuf, 0, tmpbuf.length, Deflater.SYNC_FLUSH);
             len > 0;
             len = compresser.deflate(tmpbuf, 0, tmpbuf.length, Deflater.SYNC_FLUSH)) {
            buffer.putRawBytes(tmpbuf, 0, len);
        }
    }

    @Override
    public void uncompress(Buffer from, Buffer to) throws IOException {
        decompresser.setInput(from.array(), from.rpos(), from.available());
        try {
            for (int len = decompresser.inflate(tmpbuf); len > 0; len = decompresser.inflate(tmpbuf)) {
                to.putRawBytes(tmpbuf, 0, len);
            }
        } catch (DataFormatException e) {
            throw new IOException("Error decompressing data", e);
        }
    }
}
