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

package org.apache.sshd.common.scp;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpTimestamp {
    private final long lastModifiedTime;
    private final long lastAccessTime;

    public ScpTimestamp(long modTime, long accTime) {
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
    public String toString() {
        return "modified=" + new Date(lastModifiedTime)
                + ";accessed=" + new Date(lastAccessTime);
    }

    /**
     * @param line The time specification - format:
     *             {@code T<mtime-sec> <mtime-micros> <atime-sec> <atime-micros>}
     *             where specified times are since UTC
     * @return The {@link ScpTimestamp} value with the timestamps converted to
     * <U>milliseconds</U>
     * @throws NumberFormatException if bad numerical values - <B>Note:</B>
     *                               does not check if 1st character is 'T'.
     */
    public static ScpTimestamp parseTime(String line) throws NumberFormatException {
        String[] numbers = GenericUtils.split(line.substring(1), ' ');
        return new ScpTimestamp(TimeUnit.SECONDS.toMillis(Long.parseLong(numbers[0])),
                TimeUnit.SECONDS.toMillis(Long.parseLong(numbers[2])));
    }
}
