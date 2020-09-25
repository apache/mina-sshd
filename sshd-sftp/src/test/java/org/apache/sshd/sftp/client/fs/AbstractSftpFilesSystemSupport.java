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

package org.apache.sshd.sftp.client.fs;

import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.util.Collections;
import java.util.Map;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.sftp.client.AbstractSftpClientTestSupport;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.SftpVersionSelector;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpFilesSystemSupport extends AbstractSftpClientTestSupport {
    protected AbstractSftpFilesSystemSupport() throws IOException {
        super();
    }

    protected static FileSystem createSftpFileSystem(ClientSession session, SftpVersionSelector selector) throws IOException {
        return SftpClientFactory.instance().createSftpFileSystem(session, selector);
    }

    protected URI createDefaultFileSystemURI() {
        return createDefaultFileSystemURI(Collections.emptyMap());
    }

    protected URI createDefaultFileSystemURI(Map<String, ?> params) {
        return createFileSystemURI(getCurrentTestName(), params);
    }

    protected static URI createFileSystemURI(String username, Map<String, ?> params) {
        return createFileSystemURI(username, port, params);
    }

    protected static URI createFileSystemURI(String username, int port, Map<String, ?> params) {
        return SftpFileSystemProvider.createFileSystemURI(TEST_LOCALHOST, port, username, username, params);
    }
}
