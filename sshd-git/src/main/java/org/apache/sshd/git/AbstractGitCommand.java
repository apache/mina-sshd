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

package org.apache.sshd.git;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.FileSystem;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.file.FileSystemAware;
import org.apache.sshd.server.SessionAware;
import org.apache.sshd.server.command.AbstractCommandSupport;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.ServerSessionHolder;

/**
 * Provides basic support for GIT command implementations
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractGitCommand
        extends AbstractCommandSupport
        implements SessionAware, FileSystemAware, ServerSessionHolder, GitLocationResolverCarrier {
    public static final int CHAR = 0x001;
    public static final int DELIMITER = 0x002;
    public static final int STARTQUOTE = 0x004;
    public static final int ENDQUOTE = 0x008;

    private final GitLocationResolver rootDirResolver;
    private FileSystem fileSystem;
    private ServerSession session;

    protected AbstractGitCommand(GitLocationResolver rootDirResolver, String command, ExecutorService executorService, boolean shutdownOnExit) {
        super(command, executorService, shutdownOnExit);
        this.rootDirResolver = Objects.requireNonNull(rootDirResolver, "No GIT root directory resolver provided");
    }

    @Override
    public GitLocationResolver getGitLocationResolver() {
        return rootDirResolver;
    }

    public FileSystem getFileSystem() {
        return fileSystem;
    }

    @Override
    public void setFileSystem(FileSystem fileSystem) {
        this.fileSystem = fileSystem;
    }

    @Override
    public ServerSession getServerSession() {
        return session;
    }

    @Override
    public void setSession(ServerSession session) {
        this.session = session;
    }

    @Override
    public void setOutputStream(OutputStream out) {
        super.setOutputStream(out);
        if (out instanceof ChannelOutputStream) {
            ((ChannelOutputStream) out).setNoDelay(true);
        }
    }

    @Override
    public void setErrorStream(OutputStream err) {
        super.setErrorStream(err);
        if (err instanceof ChannelOutputStream) {
            ((ChannelOutputStream) err).setNoDelay(true);
        }
    }

    @Override
    public void destroy() {
        try {
            super.destroy();
        } finally {
            FileSystem fs = getFileSystem();
            if (fs != null) {
                try {
                    fs.close();
                } catch (UnsupportedOperationException | IOException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("destroy({}) - failed ({}) to close file system={}: {}",
                                this, e.getClass().getSimpleName(), fs, e.getMessage());
                    }
                }
            }
        }
    }

    @Override
    public String toString() {
        return super.toString() + "[session=" + getServerSession() + "]";
    }

    /**
     * Parses delimited string and returns an array containing the tokens. This
     * parser obeys quotes, so the delimiter character will be ignored if it is
     * inside of a quote. This method assumes that the quote character is not
     * included in the set of delimiter characters.
     *
     * @param value the delimited string to parse.
     * @param delim the characters delimiting the tokens.
     * @param trim {@code true} if the strings are trimmed before being added to the list
     * @return a list of string or an empty list if there are none.
     */
    public static List<String> parseDelimitedString(String value, String delim, boolean trim) {
        if (value == null) {
            value = "";
        }

        List<String> list = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        int expecting = CHAR | DELIMITER | STARTQUOTE;
        boolean isEscaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean isDelimiter = delim.indexOf(c) >= 0;
            if (!isEscaped && (c == '\\')) {
                isEscaped = true;
                continue;
            }

            if (isEscaped) {
                sb.append(c);
            } else if (isDelimiter && ((expecting & DELIMITER) != 0)) {
                if (trim) {
                    String str = sb.toString();
                    list.add(str.trim());
                } else {
                    list.add(sb.toString());
                }
                sb.delete(0, sb.length());
                expecting = CHAR | DELIMITER | STARTQUOTE;
            } else if ((c == '"') && ((expecting & STARTQUOTE) != 0)) {
                sb.append(c);
                expecting = CHAR | ENDQUOTE;
            } else if ((c == '"') && ((expecting & ENDQUOTE) != 0)) {
                sb.append(c);
                expecting = CHAR | STARTQUOTE | DELIMITER;
            } else if ((expecting & CHAR) != 0) {
                sb.append(c);
            } else {
                throw new IllegalArgumentException("Invalid delimited string: " + value);
            }

            isEscaped = false;
        }

        if (sb.length() > 0) {
            if (trim) {
                String str = sb.toString();
                list.add(str.trim());
            } else {
                list.add(sb.toString());
            }
        }

        return list;
    }
}
