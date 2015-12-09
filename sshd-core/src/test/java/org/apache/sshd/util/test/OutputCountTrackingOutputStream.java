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

package org.apache.sshd.util.test;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class OutputCountTrackingOutputStream extends FilterOutputStream {
    protected long writeCount;

    public OutputCountTrackingOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void write(int b) throws IOException {
        out.write(b);
        updateWriteCount(1L);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len); // don't call super since it calls the single 'write'
        updateWriteCount(len);
    }

    public long getWriteCount() {
        return writeCount;
    }

    protected long updateWriteCount(long delta) {
        writeCount += delta;
        return writeCount;
    }
}
