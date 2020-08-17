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
package org.apache.sshd.scp.client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.Set;

import org.apache.sshd.common.session.Session;
import org.apache.sshd.scp.common.ScpSourceStreamResolver;
import org.apache.sshd.scp.common.helpers.ScpTimestampCommandDetails;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultScpStreamResolver implements ScpSourceStreamResolver {
    private final String name;
    private final Path mockPath;
    private final Collection<PosixFilePermission> perms;
    private final ScpTimestampCommandDetails time;
    private final long size;
    private final InputStream local;
    private final String cmd;

    public DefaultScpStreamResolver(
                                    String name, Path mockPath, Collection<PosixFilePermission> perms,
                                    ScpTimestampCommandDetails time, long size, InputStream local, String cmd) {
        this.name = name;
        this.mockPath = mockPath;
        this.perms = perms;
        this.time = time;
        this.size = size;
        this.local = local;
        this.cmd = cmd;
    }

    @Override
    public String getFileName() throws java.io.IOException {
        return name;
    }

    @Override
    public Path getEventListenerFilePath() {
        return mockPath;
    }

    @Override
    public Collection<PosixFilePermission> getPermissions() throws IOException {
        return perms;
    }

    @Override
    public ScpTimestampCommandDetails getTimestamp() throws IOException {
        return time;
    }

    @Override
    public long getSize() throws IOException {
        return size;
    }

    @Override
    public InputStream resolveSourceStream(
            Session session, long length, Set<PosixFilePermission> permissions, OpenOption... options)
            throws IOException {
        return local;
    }

    @Override
    public String toString() {
        return cmd;
    }
}
