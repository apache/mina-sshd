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
package org.apache.sshd.benchmarks.sftp.upload;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@State(Scope.Benchmark)
public abstract class CommonState {

    private static final Logger LOG = LoggerFactory.getLogger(CommonState.class);

    @Param({ "jsch", "sshd" })
    protected String settings = "";

    @Param("")
    protected String sftpHost;
    @Param("")
    protected String sftpPort;
    @Param("")
    protected String sftpUser;
    @Param("")
    protected String sftpKey;
    @Param("")
    protected String initialFile;

    protected Path testData;

    protected CommonState() {
        super();
    }

    protected abstract void downloadTo(Path localPath) throws IOException;

    protected void downloadAndVerify(Path original) throws IOException {
        // Download what got uploaded and verify the two files are identical.
        Path downloaded = Files.createTempFile("dwnld", "bin");
        try {
            downloadTo(downloaded);
            if (!equalFiles(original, downloaded)) {
                LOG.error("File got corrupted in upload/download");
                throw new IOException("Files differ");
            }
        } finally {
            File f = downloaded.toFile();
            if (!f.delete() && f.isFile()) {
                f.deleteOnExit();
            }
        }
    }

    private boolean equalFiles(Path a, Path b) throws IOException {
        try (InputStream inA = new BufferedInputStream(Files.newInputStream(a));
             InputStream inB = new BufferedInputStream(Files.newInputStream(b))) {
            int byteA = inA.read();
            int byteB = inB.read();
            while (byteA >= 0 || byteB >= 0) {
                if (byteA != byteB) {
                    return false;
                }
                if (byteA < 0) {
                    return true;
                }
                byteA = inA.read();
                byteB = inB.read();
            }
        }
        return true;
    }

    protected abstract void prepare() throws Exception;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        testData = Paths.get(initialFile);
        prepare();
    }

    protected void endTests() throws Exception {
        // By default nothing.
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        endTests();
    }

    protected abstract void setupSession() throws Exception;

    @Setup(Level.Iteration)
    public void startSsh() throws Exception {
        setupSession();
    }

    protected abstract void closeSession() throws Exception;

    @TearDown(Level.Iteration)
    public void endSsh() throws Exception {
        downloadAndVerify(Paths.get(initialFile));
        closeSession();
    }
}
