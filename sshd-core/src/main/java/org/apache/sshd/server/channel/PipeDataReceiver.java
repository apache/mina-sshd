/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.server.channel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.sshd.common.channel.ChannelPipedInputStream;
import org.apache.sshd.common.channel.ChannelPipedOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.util.LoggingFilterOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link ChannelDataReceiver} that buffers the received data into byte buffer
 * and provides an {@link InputStream} to consume them.
 *
 * @author Kohsuke Kawaguchi
 */
public class PipeDataReceiver implements ChannelDataReceiver {
    private InputStream in;
    private OutputStream out;

    public PipeDataReceiver(Window localWindow) {
        ChannelPipedInputStream in = new ChannelPipedInputStream(localWindow);
        this.in = in;
        this.out = new ChannelPipedOutputStream(in);
        if (log != null && log.isTraceEnabled()) {
            out = new LoggingFilterOutputStream(out, "IN: ", log);
        }
    }

    public InputStream getIn() {
        return in;
    }

    public void close() throws IOException {
        out.close();
    }

    public int data(ChannelSession channel, byte[] buf, int start, int len) throws IOException {
        out.write(buf, start, len);
        return 0; // ChannelPipedOutputStream calls consume method on its own, so here we return 0 to make the ends meet.
    }

    protected final Logger log = LoggerFactory.getLogger(getClass());
}
