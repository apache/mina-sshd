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

package org.apache.sshd.sftp.server;

import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Map;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.session.ServerSession;

/**
 * A no-op implementation of {@link SftpEventListener} for those who wish to implement only a small number of methods.
 * By default, all non-overridden methods simply log at TRACE level their invocation parameters
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSftpEventListenerAdapter extends AbstractLoggingBean implements SftpEventListener {
    protected AbstractSftpEventListenerAdapter() {
        super();
    }

    @Override
    public void initialized(ServerSession session, int version) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("initialized(" + session + ") version: " + version);
        }
    }

    @Override
    public void destroying(ServerSession session) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("destroying(" + session + ")");
        }
    }

    @Override
    public void opening(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
        if (log.isTraceEnabled()) {
            Path path = localHandle.getFile();
            log.trace("opening(" + session + ")[" + remoteHandle + "] " + (Files.isDirectory(path) ? "directory" : "file") + " "
                      + path);
        }
    }

    @Override
    public void open(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
        if (log.isTraceEnabled()) {
            Path path = localHandle.getFile();
            log.trace("open(" + session + ")[" + remoteHandle + "] " + (Files.isDirectory(path) ? "directory" : "file") + " "
                      + path);
        }
    }

    @Override
    public void readEntries(ServerSession session, String remoteHandle, DirectoryHandle localHandle, Map<String, Path> entries)
            throws IOException {
        int numEntries = GenericUtils.size(entries);
        if (log.isDebugEnabled()) {
            log.debug("read(" + session + ")[" + localHandle.getFile() + "] " + numEntries + " entries");
        }

        if ((numEntries > 0) && log.isTraceEnabled()) {
            entries.forEach(
                    (key, value) -> log.trace("read(" + session + ")[" + localHandle.getFile() + "] " + key + " - " + value));
        }
    }

    @Override
    public void reading(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("reading(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", requested=" + dataLen);
        }
    }

    @Override
    @SuppressWarnings("checkstyle:ParameterNumber")
    public void read(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen, int readLen, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("read(" + session + ")[" + localHandle.getFile() + "] offset=" + offset
                      + ", requested=" + dataLen + ", read=" + readLen
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void writing(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("write(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", requested=" + dataLen);
        }
    }

    @Override
    public void written(
            ServerSession session, String remoteHandle, FileHandle localHandle,
            long offset, byte[] data, int dataOffset, int dataLen, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("written(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", requested=" + dataLen
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void blocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, int mask)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("blocking(" + session + ")[" + localHandle.getFile() + "]"
                      + " offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask));
        }
    }

    @Override
    public void blocked(
            ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, int mask,
            Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("blocked(" + session + ")[" + localHandle.getFile() + "]"
                      + " offset=" + offset + ", length=" + length + ", mask=0x" + Integer.toHexString(mask)
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void unblocking(ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("unblocking(" + session + ")[" + localHandle.getFile() + "] offset=" + offset + ", length=" + length);
        }
    }

    @Override
    public void unblocked(
            ServerSession session, String remoteHandle, FileHandle localHandle, long offset, long length, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("unblocked(" + session + ")[" + localHandle.getFile() + "]"
                      + " offset=" + offset + ", length=" + length
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void closing(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
        if (log.isTraceEnabled()) {
            Path path = localHandle.getFile();
            log.trace("close(" + session + ")[" + remoteHandle + "] " + (Files.isDirectory(path) ? "directory" : "file") + " "
                      + path);
        }
    }

    @Override
    public void creating(ServerSession session, Path path, Map<String, ?> attrs)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("creating(" + session + ") " + (Files.isDirectory(path) ? "directory" : "file") + " " + path);
        }
    }

    @Override
    public void created(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("created(" + session + ") " + (Files.isDirectory(path) ? "directory" : "file") + " " + path
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void moving(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("moving(" + session + ")[" + opts + "]" + srcPath + " => " + dstPath);
        }
    }

    @Override
    public void moved(ServerSession session, Path srcPath, Path dstPath, Collection<CopyOption> opts, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("moved(" + session + ")[" + opts + "]" + srcPath + " => " + dstPath
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void removing(ServerSession session, Path path, boolean isDirectory)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("removing(" + session + ")[dir=" + isDirectory + "] " + path);
        }
    }

    @Override
    public void removed(ServerSession session, Path path, boolean isDirectory, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("removed(" + session + ")[dir=" + isDirectory + "] " + path
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void linking(ServerSession session, Path source, Path target, boolean symLink)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("linking(" + session + ")[" + symLink + "]" + source + " => " + target);
        }
    }

    @Override
    public void linked(ServerSession session, Path source, Path target, boolean symLink, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("linked(" + session + ")[" + symLink + "]" + source + " => " + target
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }

    @Override
    public void modifyingAttributes(ServerSession session, Path path, Map<String, ?> attrs)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("modifyingAttributes(" + session + ") " + path + ": " + attrs);
        }
    }

    @Override
    public void modifiedAttributes(ServerSession session, Path path, Map<String, ?> attrs, Throwable thrown)
            throws IOException {
        if (log.isTraceEnabled()) {
            log.trace("modifiedAttributes(" + session + ") " + path
                      + ((thrown == null) ? "" : (": " + thrown.getClass().getSimpleName() + ": " + thrown.getMessage())));
        }
    }
}
