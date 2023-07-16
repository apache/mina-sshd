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
package org.apache.sshd.common.util.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * A snapshot of file metadata that can be used to determine whether a file has been modified since the last time it was
 * read. Intended usage:
 *
 * <pre>
 * FileSnapshot fileSnapshot = FileSnapshot.save(path);
 * byte[] content = Files.readAllBytes(path);
 * ...
 * FileSnapshot newSnapshot = oldSnapshot.reload(path);
 * if (newSnapshot == fileSnapshot) {
 *   // File was not modified
 * } else {
 *   // File may have been modified
 *   fileSnapshot = newSnapshot;
 *   content = Files.readAllBytes(path);
 * }
 * </pre>
 *
 * <p>
 * File modifications that occur quicker than the resolution of the system's "last modified" timestamp of a file cannot
 * be detected reliably. This implementation assumes a worst-case filesystem timestamp resolution of 2 seconds (as it
 * exists on FAT file systems). A snapshot taken within 2 seconds since the last modified time is considered "racily
 * clean" only: the file will be considered potentially modified even if the metadata matches.
 * </p>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FileSnapshot {

    /**
     * A value indicating an unknown file size.
     */
    public static final long UNKNOWN_SIZE = -1L;

    /**
     * A {@link FileSnapshot} describing a non-existing file.
     */
    public static final FileSnapshot NO_FILE = new FileSnapshot(Instant.now(), null, UNKNOWN_SIZE, null);

    // FAT has a truly crude timestamp resolution.
    private static final Duration WORST_CASE_TIMESTAMP_RESOLUTION = Duration.ofMillis(2000);

    // File metadata
    private final FileTime lastModified;
    private final long size;
    private final Object fileKey;

    // The time the snapshot was taken; needed to determine whether it might be "racily clean"
    private final Instant snapTime;

    /**
     * Creates a new {@link FileSnapshot} instance.
     *
     * @param snapTime     the {@link Instant} the snapshot was taken
     * @param lastModified the "last modified" {@link FileTime}
     * @param size         the file size
     * @param fileKey      the file key
     */
    protected FileSnapshot(Instant snapTime, FileTime lastModified, long size, Object fileKey) {
        this.snapTime = Objects.requireNonNull(snapTime);
        this.lastModified = lastModified;
        this.size = size;
        this.fileKey = fileKey;
    }

    /**
     * Retrieves the "last modified" time as recorded in this {@link FileSnapshot}.
     *
     * @return the {@link FileTime}, may be {@code null}
     */
    protected FileTime getLastModified() {
        return lastModified;
    }

    /**
     * Retrieves the file size as recorded in this {@link FileSnapshot}.
     *
     * @return the size, {@link #UNKNOWN_SIZE} for a snapshot of a non-existing file
     */
    protected long getSize() {
        return size;
    }

    /**
     * Retrieves the file key as recorded in this {@link FileSnapshot}.
     *
     * @return the file key, may be {@code null}
     */
    protected Object getFileKey() {
        return fileKey;
    }

    /**
     * Retrieves the time this {@link FileSnapshot} was taken.
     *
     * @return the {@link Instant} the snapshot was taken, never {@code null}
     */
    protected Instant getTime() {
        return snapTime;
    }

    /**
     * Creates a new {@link FileSnapshot} for the given path.
     *
     * @param  file        to take the snapshot of
     * @param  options     {@link LinkOption}s to use
     * @return             the {@link FileSnapshot}, never {@code null}
     * @throws IOException if an I/O error occurs
     */
    public static FileSnapshot save(Path file, LinkOption... options) throws IOException {
        BasicFileAttributes attributes = null;
        Instant now = Instant.now();
        try {
            attributes = Files.readAttributes(file, BasicFileAttributes.class, options);
        } catch (NoSuchFileException e) {
            return NO_FILE;
        }
        if (attributes == null) {
            return NO_FILE;
        }
        return new FileSnapshot(now, attributes.lastModifiedTime(), attributes.size(), attributes.fileKey());
    }

    /**
     * Reload the {@link FileSnapshot} for the given file.
     *
     * @param  file        to take the snapshot of
     * @param  options     {@link LinkOption}s to use
     * @return             a {@link FileSnapshot}, never {@code null}; if {@code == this}, the file may be assumed
     *                     unmodified
     * @throws IOException if an I/O error occurs
     */
    public FileSnapshot reload(Path file, LinkOption... options) throws IOException {
        FileSnapshot newSnapshot = save(file, options);
        if (newSnapshot.mayBeRacilyClean()) {
            return newSnapshot;
        }
        return same(newSnapshot) && !mayBeRacilyClean() ? this : newSnapshot;
    }

    /**
     * Determines whether this {@link FileSnapshot} was taken within the file timestamp resolution of the file system
     * after the last modified time of the file.
     *
     * @return {@code true} if so, {@code false} otherwise
     */
    protected boolean mayBeRacilyClean() {
        FileTime fTime = getLastModified();
        return fTime != null && Duration.between(fTime.toInstant(), getTime()).compareTo(WORST_CASE_TIMESTAMP_RESOLUTION) <= 0;
    }

    /**
     * Compares the snapshots' file metadata.
     *
     * @param  other {@link FileSnapshot} to compare to (should be for the same {@link Path})
     * @return       {@code true} if the two snapshots have the same file metadata, {@code false} otherwise
     */
    public boolean same(FileSnapshot other) {
        if (this == other) {
            return true;
        }
        if (other == null) {
            return false;
        }
        return Objects.equals(getFileKey(), other.getFileKey()) && Objects.equals(getLastModified(), other.getLastModified())
                && getSize() == other.getSize();
    }
}
