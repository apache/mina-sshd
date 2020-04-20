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

package org.apache.sshd.common.util;

import java.io.Serializable;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class VersionInfo implements Serializable, Comparable<VersionInfo> {
    private static final long serialVersionUID = -9127482432228413836L;

    private final int majorVersion;
    private final int minorVersion;
    private final int release;
    private final int buildNumber;

    public VersionInfo(int major, int minor) {
        this(major, minor, 0, 0);
    }

    public VersionInfo(int major, int minor, int release, int build) {
        this.majorVersion = major;
        this.minorVersion = minor;
        this.release = release;
        this.buildNumber = build;
    }

    public final int getMajorVersion() {
        return majorVersion;
    }

    public final int getMinorVersion() {
        return minorVersion;
    }

    public final int getRelease() {
        return release;
    }

    public final int getBuildNumber() {
        return buildNumber;
    }

    @Override
    public int hashCode() {
        return NumberUtils.hashCode(getMajorVersion(), getMinorVersion(), getRelease(), getBuildNumber());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        return compareTo((VersionInfo) obj) == 0;
    }

    @Override
    public int compareTo(VersionInfo o) {
        if (o == null) {
            return -1; // push nulls to end
        }
        if (o == this) {
            return 0;
        }

        int nRes = Integer.compare(getMajorVersion(), o.getMajorVersion());
        if (nRes == 0) {
            nRes = Integer.compare(getMinorVersion(), o.getMinorVersion());
        }
        if (nRes == 0) {
            nRes = Integer.compare(getRelease(), o.getRelease());
        }
        if (nRes == 0) {
            nRes = Integer.compare(getBuildNumber(), o.getBuildNumber());
        }

        return nRes;
    }

    @Override
    public String toString() {
        return NumberUtils.join('.', getMajorVersion(), getMinorVersion(), getRelease(), getBuildNumber());
    }

    /**
     * Parses a version string - assumed to contain at most 4 non-negative components separated by a '.'. If less than 4
     * components are found, then the rest are assumed to be zero. If more than 4 components found, then only the 1st
     * ones are parsed.
     *
     * @param  version                  The version string - ignored if {@code null}/empty
     * @return                          The parsed {@link VersionInfo} - or {@code null} if empty input
     * @throws NumberFormatException    If failed to parse any of the components
     * @throws IllegalArgumentException If any of the parsed components is negative
     */
    public static VersionInfo parse(String version) throws NumberFormatException {
        String[] comps = GenericUtils.split(version, '.');
        if (GenericUtils.isEmpty(comps)) {
            return null;
        }

        int[] values = new int[4];
        int maxValues = Math.min(comps.length, values.length);
        for (int index = 0; index < maxValues; index++) {
            String c = comps[index];
            int v = Integer.parseInt(c);
            ValidateUtils.checkTrue(v >= 0, "Invalid version component in %s", version);
            values[index] = v;
        }

        return new VersionInfo(values[0], values[1], values[2], values[3]);
    }
}
