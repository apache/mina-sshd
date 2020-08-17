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

package org.apache.sshd.scp.common.helpers;

import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@SuppressWarnings("PMD.AvoidUsingOctalValues")
public abstract class ScpPathCommandDetailsSupport extends AbstractScpCommandDetails implements NamedResource {
    // File permissions masks
    public static final int S_IRUSR = 0000400;
    public static final int S_IWUSR = 0000200;
    public static final int S_IXUSR = 0000100;
    public static final int S_IRGRP = 0000040;
    public static final int S_IWGRP = 0000020;
    public static final int S_IXGRP = 0000010;
    public static final int S_IROTH = 0000004;
    public static final int S_IWOTH = 0000002;
    public static final int S_IXOTH = 0000001;

    private Set<PosixFilePermission> permissions;
    private long length;
    private String name;

    protected ScpPathCommandDetailsSupport(char command) {
        super(command);
    }

    protected ScpPathCommandDetailsSupport(char command, String header) {
        super(command);

        ValidateUtils.checkNotNullAndNotEmpty(header, "No header provided");
        if (header.charAt(0) != command) {
            throw new IllegalArgumentException("Expected a '" + command + "' message but got '" + header + "'");
        }

        permissions = parseOctalPermissions(header.substring(1, 5));
        length = Long.parseLong(header.substring(6, header.indexOf(' ', 6)));
        name = header.substring(header.indexOf(' ', 6) + 1);
    }

    public Set<PosixFilePermission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<PosixFilePermission> permissions) {
        this.permissions = permissions;
    }

    public long getLength() {
        return length;
    }

    protected long getEffectiveLength() {
        return getLength();
    }

    public void setLength(long length) {
        this.length = length;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toHeader() {
        return getCommand() + getOctalPermissions(getPermissions()) + " " + getEffectiveLength() + " " + getName();
    }

    @Override
    public int hashCode() {
        return Character.hashCode(getCommand())
               + 31 * Objects.hashCode(getName())
               + 37 * Long.hashCode(getEffectiveLength())
               + 41 * GenericUtils.size(getPermissions());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        ScpPathCommandDetailsSupport other = (ScpPathCommandDetailsSupport) obj;
        return (getCommand() == other.getCommand())
                && (getEffectiveLength() == other.getEffectiveLength())
                && Objects.equals(getName(), other.getName())
                && GenericUtils.equals(getPermissions(), other.getPermissions());
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[name=" + getName()
               + ", len=" + getLength()
               + ", perms=" + getPermissions()
               + "]";
    }

    public static String getOctalPermissions(Collection<PosixFilePermission> perms) {
        int pf = 0;

        for (PosixFilePermission p : perms) {
            switch (p) {
                case OWNER_READ:
                    pf |= S_IRUSR;
                    break;
                case OWNER_WRITE:
                    pf |= S_IWUSR;
                    break;
                case OWNER_EXECUTE:
                    pf |= S_IXUSR;
                    break;
                case GROUP_READ:
                    pf |= S_IRGRP;
                    break;
                case GROUP_WRITE:
                    pf |= S_IWGRP;
                    break;
                case GROUP_EXECUTE:
                    pf |= S_IXGRP;
                    break;
                case OTHERS_READ:
                    pf |= S_IROTH;
                    break;
                case OTHERS_WRITE:
                    pf |= S_IWOTH;
                    break;
                case OTHERS_EXECUTE:
                    pf |= S_IXOTH;
                    break;
                default: // ignored
            }
        }

        return String.format("%04o", pf);
    }

    public static Set<PosixFilePermission> parseOctalPermissions(String str) {
        int perms = Integer.parseInt(str, 8);
        Set<PosixFilePermission> p = EnumSet.noneOf(PosixFilePermission.class);
        if ((perms & S_IRUSR) != 0) {
            p.add(PosixFilePermission.OWNER_READ);
        }
        if ((perms & S_IWUSR) != 0) {
            p.add(PosixFilePermission.OWNER_WRITE);
        }
        if ((perms & S_IXUSR) != 0) {
            p.add(PosixFilePermission.OWNER_EXECUTE);
        }
        if ((perms & S_IRGRP) != 0) {
            p.add(PosixFilePermission.GROUP_READ);
        }
        if ((perms & S_IWGRP) != 0) {
            p.add(PosixFilePermission.GROUP_WRITE);
        }
        if ((perms & S_IXGRP) != 0) {
            p.add(PosixFilePermission.GROUP_EXECUTE);
        }
        if ((perms & S_IROTH) != 0) {
            p.add(PosixFilePermission.OTHERS_READ);
        }
        if ((perms & S_IWOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_WRITE);
        }
        if ((perms & S_IXOTH) != 0) {
            p.add(PosixFilePermission.OTHERS_EXECUTE);
        }

        return p;
    }
}
