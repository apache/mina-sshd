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

package org.apache.sshd.scp.common;

import java.nio.file.attribute.FileTime;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.scp.common.helpers.AbstractScpCommandDetails;

/**
 * Represents an SCP timestamp definition
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpTimestamp extends AbstractScpCommandDetails {
    public static final char COMMAND_NAME = 'T';

    private final long lastModifiedTime;
    private final long lastAccessTime;

    public ScpTimestamp(String header) {
        super(COMMAND_NAME);

        if (header.charAt(0) != COMMAND_NAME) {
            throw new IllegalArgumentException("Expected a '" + COMMAND_NAME + "' but got '" + header + "'");
        }

        String[] numbers = GenericUtils.split(header.substring(1), ' ');
        lastModifiedTime = TimeUnit.SECONDS.toMillis(Long.parseLong(numbers[0]));
        lastAccessTime = TimeUnit.SECONDS.toMillis(Long.parseLong(numbers[2]));
    }

    public ScpTimestamp(FileTime modTime, FileTime accTime) {
        this(modTime.to(TimeUnit.MILLISECONDS), accTime.to(TimeUnit.MILLISECONDS));
    }

    public ScpTimestamp(long modTime, long accTime) {
        super(COMMAND_NAME);

        lastModifiedTime = modTime;
        lastAccessTime = accTime;
    }

    public long getLastModifiedTime() {
        return lastModifiedTime;
    }

    public long getLastAccessTime() {
        return lastAccessTime;
    }

    @Override
    public String toHeader() {
        return Character.toString(getCommand()) + TimeUnit.MILLISECONDS.toSeconds(getLastModifiedTime())
               + " 0 " + TimeUnit.MILLISECONDS.toSeconds(getLastAccessTime()) + "0";
    }

    @Override
    public String toString() {
        return "modified=" + new Date(lastModifiedTime)
               + ";accessed=" + new Date(lastAccessTime);
    }

    /**
     * @param  line                  The time specification - format:
     *                               {@code T<mtime-sec> <mtime-micros> <atime-sec> <atime-micros>} where specified
     *                               times are in seconds since UTC - ignored if {@code null}
     * @return                       The {@link ScpTimestamp} value with the timestamps converted to <U>milliseconds</U>
     * @throws NumberFormatException if bad numerical values - <B>Note:</B> validates that 1st character is 'T'.
     * @see                          <A HREF="https://blogs.oracle.com/janp/entry/how_the_scp_protocol_works">How the
     *                               SCP protocol works</A>
     */
    public static ScpTimestamp parseTime(String line) throws NumberFormatException {
        return GenericUtils.isEmpty(line) ? null : new ScpTimestamp(line);
    }
}
