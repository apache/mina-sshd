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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.CommonModuleProperties;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.apache.sshd.common.util.logging.SimplifiedLog;
import org.slf4j.Logger;

/**
 * Dumps everything that is written to the stream to the logger
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class LoggingFilterOutputStream extends FilterOutputStream {

    private final String msg;
    private final SimplifiedLog log;
    private final int chunkSize;
    private final AtomicInteger writeCount = new AtomicInteger(0);

    public LoggingFilterOutputStream(OutputStream out, String msg, Logger log, PropertyResolver resolver) {
        this(out, msg, log, CommonModuleProperties.HEXDUMP_CHUNK_SIZE.getRequired(resolver));
    }

    public LoggingFilterOutputStream(OutputStream out, String msg, Logger log, int chunkSize) {
        super(out);
        this.msg = msg;
        this.log = LoggingUtils.wrap(log);
        this.chunkSize = chunkSize;
    }

    @Override
    public void write(int b) throws IOException {
        byte[] d = new byte[1];
        d[0] = (byte) b;
        write(d, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        int count = writeCount.incrementAndGet();
        BufferUtils.dumpHex(log, BufferUtils.DEFAULT_HEXDUMP_LEVEL, msg + "[" + count + "]", BufferUtils.DEFAULT_HEX_SEPARATOR,
                chunkSize, b, off, len);
        out.write(b, off, len);
    }
}
