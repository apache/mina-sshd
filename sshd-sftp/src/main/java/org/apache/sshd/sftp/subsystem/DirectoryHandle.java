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

import org.apache.sshd.common.file.SshFile;

import java.util.Iterator;
import java.util.List;

public class DirectoryHandle extends BaseHandle implements Iterator<SshFile> {

    boolean done;
    // the directory should be read once at "open directory"
    List<SshFile> fileList = null;
    int fileIndex;

    public DirectoryHandle(String id, SshFile file) {
        super(id, file);
        fileList = file.listSshFiles();
        fileIndex = 0;
    }

    public boolean isDone() {
        return done;
    }

    public void setDone(boolean done) {
        this.done = done;
    }

    public boolean hasNext() {
        return fileIndex < fileList.size();
    }

    public SshFile next() {
        SshFile f = fileList.get(fileIndex);
        fileIndex++;
        return f;
    }

    public void remove() {
        throw new UnsupportedOperationException();
    }

    public void clearFileList() {
        // allow the garbage collector to do the job
        fileList = null;
    }
}
