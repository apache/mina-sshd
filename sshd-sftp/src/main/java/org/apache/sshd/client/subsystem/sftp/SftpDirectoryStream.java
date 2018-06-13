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
package org.apache.sshd.client.subsystem.sftp;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.Iterator;

/**
 * Implements a remote {@link DirectoryStream}
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SftpDirectoryStream implements DirectoryStream<Path> {
    private final SftpClient sftp;
    private final Iterable<SftpClient.DirEntry> iter;
    private final SftpPath p;

    /**
     * @param path The remote {@link SftpPath}
     * @throws IOException If failed to initialize the directory access handle
     */
    public SftpDirectoryStream(SftpPath path) throws IOException {
        SftpFileSystem fs = path.getFileSystem();
        p = path;
        sftp = fs.getClient();
        iter = sftp.readDir(path.toString());
    }

    /**
     * Client instance used to access the remote directory
     *
     * @return The {@link SftpClient} instance used to access the remote directory
     */
    public final SftpClient getClient() {
        return sftp;
    }

    @Override
    public Iterator<Path> iterator() {
        return new SftpPathIterator(p, iter);
    }

    @Override
    public void close() throws IOException {
        sftp.close();
    }
}