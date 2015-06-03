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

package org.apache.sshd.common.util.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sshd.common.util.AbstractLoggingBean;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.IoUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Watches over changes for a file and re-loads them if file has changed - including
 * if file is deleted or (re-)created
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ModifiableFileWatcher extends AbstractLoggingBean {
    private final Path file;
    private final AtomicBoolean lastExisted = new AtomicBoolean(false);
    private final AtomicLong lastSize = new AtomicLong(Long.MIN_VALUE);
    private final AtomicLong lastModified = new AtomicLong(-1L);
    protected final LinkOption[] options;

    public ModifiableFileWatcher(File file) {
        this(ValidateUtils.checkNotNull(file, "No file to watch", GenericUtils.EMPTY_OBJECT_ARRAY).toPath());
    }

    public ModifiableFileWatcher(Path file) {
        this(file, IoUtils.getLinkOptions(false));
    }

    public ModifiableFileWatcher(Path file, LinkOption ... options) {
        this.file = ValidateUtils.checkNotNull(file, "No path to watch", GenericUtils.EMPTY_OBJECT_ARRAY);
        // use a clone to avoid being sensitive to changes in the passed array
        this.options = (options == null) ? IoUtils.EMPTY_OPTIONS : options.clone();
    }
    
    /**
     * @return The watched {@link Path}
     */
    public final Path getPath() {
        return file;
    }
    
    public final boolean exists() throws IOException {
        return Files.exists(getPath(), options);
    }

    public final long size() throws IOException {
        if (exists()) {
            return Files.size(getPath());
        } else {
            return (-1L);
        }
    }

    public final FileTime lastModified() throws IOException {
        if (exists()) {
            BasicFileAttributes attrs = Files.readAttributes(getPath(), BasicFileAttributes.class, options);
            return attrs.lastModifiedTime();
        } else {
            return null;
        }
    }

    /**
     * @return {@code true} if the watched file has probably been changed
     * @throws IOException If failed to query file data
     */
    public boolean checkReloadRequired() throws IOException {
        boolean exists = exists();
        // if existence state changed from last time
        if (exists != lastExisted.getAndSet(exists)) {
            return true;
        }
        
        if (!exists) {
            // file did not exist and still does not exist
            resetReloadAttributes();
            return false;
        }
        
        long size = size();
        if (size < 0L) {
            // means file no longer exists
            resetReloadAttributes();
            return true;
        }

        // if size changed then obviously need reload
        if (size != lastSize.getAndSet(size)) {
            return true;
        }

        FileTime modifiedTime = lastModified();
        if (modifiedTime == null) {
            // means file no longer exists
            resetReloadAttributes();
            return true;
        }

        long timestamp = modifiedTime.toMillis();
        if (timestamp != lastModified.getAndSet(timestamp)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Resets the state attributes used to detect changes to the initial
     * construction values - i.e., file assumed not to exist and no known
     * size of modify time
     */
    public void resetReloadAttributes() {
        lastExisted.set(false);
        lastSize.set(Long.MIN_VALUE);
        lastModified.set(-1L);
    }

    /**
     * May be called to refresh the state attributes used to detect changes
     * e.g., file existence, size and last-modified time once re-loading is
     * successfully completed. If the file does not exist then the attributes
     * are reset to an &quot;unknown&quot; state.
     * @throws IOException If failed to access the file (if exists)
     * @see #resetReloadAttributes()
     */
    public void updateReloadAttributes() throws IOException {
        if (exists()) {
            long size = size();
            FileTime modifiedTime = lastModified();

            if ((size >= 0L) && (modifiedTime != null)) {
                lastExisted.set(true);
                lastSize.set(size);
                lastModified.set(modifiedTime.toMillis());
                return;
            }
        }

        resetReloadAttributes();
    }
}
