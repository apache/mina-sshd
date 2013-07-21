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
package org.apache.sshd.sftp.subsystem;

import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.file.SshFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FileHandle extends BaseHandle {

    int flags;
    OutputStream output;
    long outputPos;
    InputStream input;
    long inputPos;
    long length;

    public FileHandle(String id, SshFile sshFile, int flags) {
        super(id, sshFile);
        this.flags = flags;
    }

    public int getFlags() {
        return flags;
    }

    public int read(byte[] data, long offset) throws IOException {
        if (input != null && offset >= length) {
            return -1;
        }
        if (input != null && offset != inputPos) {
            IoUtils.closeQuietly(input);
            input = null;
        }
        if (input == null) {
            input = getFile().createInputStream(offset);
            length = getFile().getSize();
            inputPos = offset;
        }
        if (offset >= length) {
            return -1;
        }
        int read = input.read(data);
        inputPos += read;
        return read;
    }

    public void write(byte[] data, long offset) throws IOException {
        if (output != null && offset != outputPos) {
            IoUtils.closeQuietly(output);
            output = null;
        }
        if (output == null) {
            output = getFile().createOutputStream(offset);
        }
        output.write(data);
        outputPos += data.length;
    }

    @Override
    public void close() throws IOException {
        IoUtils.closeQuietly(output, input);
        output = null;
        input = null;
        super.close();
    }
}
