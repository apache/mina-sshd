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
import java.io.StreamCorruptedException;

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CompressionNone extends BaseCompression {
    private Type type;
    private int level;

    public CompressionNone() {
        super(BuiltinCompressions.Constants.NONE);
    }

    @Override
    public void init(Type type, int level) {
        this.type = type;
        this.level = level;
    }

    @Override
    public boolean isCompressionExecuted() {
        return false;
    }

    @Override
    public void compress(Buffer buffer) throws IOException {
        if (!Type.Deflater.equals(type)) {
            throw new StreamCorruptedException("Not set up for compression: " + type);
        }
    }

    @Override
    public void uncompress(Buffer from, Buffer to) throws IOException {
        if (!Type.Inflater.equals(type)) {
            throw new StreamCorruptedException("Not set up for de-compression: " + type);
        }

        if (from != to) {
            throw new StreamCorruptedException("Separate de-compression buffers provided");
        }
    }

    @Override
    public boolean isDelayed() {
        return false;
    }

    @Override
    public String toString() {
        return super.toString() + "[" + type + "/" + level + "]";
    }
}
