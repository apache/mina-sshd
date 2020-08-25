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

import java.io.Serializable;
import java.util.Objects;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.auth.MutableUserHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.OsUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Represents a local or remote SCP location in the format &quot;user@host:path&quot; or
 * &quot;scp://[user@]host[:port][/path]&quot; for a remote path and a simple path for a local one. If user is omitted
 * for a remote path then current user is used.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpLocation implements MutableUserHolder, Serializable, Cloneable {
    public static final String SCHEME = "scp://";
    public static final char HOST_PART_SEPARATOR = ':';
    public static final char USERNAME_PART_SEPARATOR = '@';

    private static final long serialVersionUID = 5450230457030600136L;

    private String host;
    private String username;
    private String path;
    private int port;

    public ScpLocation() {
        this(null);
    }

    /**
     * @param  locSpec                  The location specification - ignored if {@code null}/empty
     * @see                             #update(String, ScpLocation)
     * @throws IllegalArgumentException if invalid specification
     */
    public ScpLocation(String locSpec) {
        update(locSpec, this);
    }

    public ScpLocation(String username, String host, String path) {
        this(username, host, 0, path);
    }

    public ScpLocation(String username, String host, int port, String path) {
        this.username = username;
        this.host = host;
        this.port = port;
        this.path = path;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public boolean isLocal() {
        return GenericUtils.isEmpty(getHost());
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public int resolvePort() {
        return SshConstants.TO_EFFECTIVE_PORT.applyAsInt(getPort());
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Resolves the effective username to use for a remote location. If username not set then uses the current username
     *
     * @return The resolved username
     * @see    #getUsername()
     * @see    OsUtils#getCurrentUser()
     */
    public String resolveUsername() {
        String user = getUsername();
        if (GenericUtils.isEmpty(user)) {
            return OsUtils.getCurrentUser();
        } else {
            return user;
        }
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public int hashCode() {
        return isLocal()
                ? Objects.hashCode(OsUtils.getComparablePath(getPath()))
                : Objects.hash(getHost(), resolveUsername(), OsUtils.getComparablePath(getPath()))
                  + 31 * Integer.hashCode(resolvePort());
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

        ScpLocation other = (ScpLocation) obj;
        boolean thisLocal = this.isLocal();
        if (thisLocal != other.isLocal()) {
            return false;
        }

        String thisPath = OsUtils.getComparablePath(getPath());
        String otherPath = OsUtils.getComparablePath(other.getPath());
        if (!Objects.equals(thisPath, otherPath)) {
            return false;
        }

        if (thisLocal) {
            return true;
        }

        // we know other is also remote or we would not have reached this point
        return Objects.equals(resolveUsername(), other.resolveUsername())
                && Objects.equals(getHost(), other.getHost())
                && (resolvePort() == other.resolvePort());
    }

    @Override
    public ScpLocation clone() {
        try {
            return getClass().cast(super.clone());
        } catch (CloneNotSupportedException e) { // unexpected
            throw new RuntimeException("Failed to clone " + toString(), e);
        }
    }

    @Override
    public String toString() {
        String p = getPath();
        if (isLocal()) {
            return p;
        }

        int portValue = resolvePort();
        String userValue = resolveUsername();
        StringBuilder sb = new StringBuilder();
        if (portValue != SshConstants.DEFAULT_PORT) {
            sb.append(SCHEME);
        }
        sb.append(userValue).append(USERNAME_PART_SEPARATOR).append(getHost());
        sb.append(HOST_PART_SEPARATOR);
        if (portValue != SshConstants.DEFAULT_PORT) {
            sb.append(portValue);
        }
        sb.append(p);

        return sb.toString();
    }

    /**
     * Parses a local or remote SCP location in the format &quot;user@host:path&quot; or
     * &quot;scp://[user@]host[:port][/path]&quot;
     *
     * @param  locSpec                  The location specification - ignored if {@code null}/empty
     * @return                          The {@link ScpLocation} or {@code null} if no specification provider
     * @throws IllegalArgumentException if invalid specification
     * @see                             #update(String, ScpLocation)
     */
    public static ScpLocation parse(String locSpec) {
        return GenericUtils.isEmpty(locSpec) ? null : update(locSpec, new ScpLocation());
    }

    /**
     * Parses a local or remote SCP location in the format &quot;user@host:path&quot; or
     * &quot;scp://[user@]host[:port][/path]&quot;
     *
     * @param  <L>                      Type of {@link ScpLocation} being updated
     * @param  spec                     The location specification - ignored if {@code null}/empty
     * @param  location                 The {@link ScpLocation} to update - never {@code null}
     * @return                          The updated location (unless no specification)
     * @throws IllegalArgumentException if invalid specification
     */
    public static <L extends ScpLocation> L update(String spec, L location) {
        Objects.requireNonNull(location, "No location to update");
        if (GenericUtils.isEmpty(spec)) {
            return location;
        }

        location.setHost(null);
        location.setUsername(null);
        location.setPort(0);

        String login;
        if (spec.startsWith(SCHEME)) {
            int pos = spec.indexOf('/', SCHEME.length());
            ValidateUtils.checkTrue(pos > 0, "Invalid remote specification (missing path specification): %s", spec);

            login = spec.substring(SCHEME.length(), pos);
            location.setPath(spec.substring(pos));

            pos = login.indexOf(HOST_PART_SEPARATOR);
            ValidateUtils.checkTrue(pos != 0, "Invalid remote specification (malformed port specification): %s", spec);
            if (pos > 0) {
                ValidateUtils.checkTrue(pos < (login.length() - 1), "Invalid remote specification (no port specification): %s",
                        spec);
                location.setPort(Integer.parseInt(login.substring(pos + 1)));
                login = login.substring(0, pos);
            }
        } else {
            int pos = spec.indexOf(HOST_PART_SEPARATOR);
            if (pos < 0) { // assume a local path
                location.setPath(spec);
                return location;
            }

            /*
             * NOTE !!! in such a case there may be confusion with a host named 'a', but there is a limit to how smart we
             * can be...
             */
            if ((pos == 1) && OsUtils.isWin32()) {
                char drive = spec.charAt(0);
                if (((drive >= 'a') && (drive <= 'z')) || ((drive >= 'A') && (drive <= 'Z'))) {
                    location.setPath(spec);
                    return location;
                }
            }

            login = spec.substring(0, pos);
            ValidateUtils.checkTrue(pos < (spec.length() - 1), "Invalid remote specification (missing path): %s", spec);
            location.setPath(spec.substring(pos + 1));
        }

        int pos = login.indexOf(USERNAME_PART_SEPARATOR);
        ValidateUtils.checkTrue(pos != 0, "Invalid remote specification (missing username): %s", spec);
        if (pos < 0) {
            location.setHost(login);
        } else {
            location.setUsername(login.substring(0, pos));
            ValidateUtils.checkTrue(pos < (login.length() - 1), "Invalid remote specification (missing host): %s", spec);
            location.setHost(login.substring(pos + 1));
        }

        return location;
    }
}
