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

package org.apache.sshd.sftp.common.extensions.openssh;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.sftp.common.extensions.AbstractParser;
import org.apache.sshd.sftp.common.extensions.openssh.AbstractOpenSSHExtensionParser.OpenSSHExtension;

/**
 * Base class for various {@code XXX@openssh.com} extension data reports
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractOpenSSHExtensionParser extends AbstractParser<OpenSSHExtension> {
    public static class OpenSSHExtension implements NamedResource, Cloneable, Serializable {
        private static final long serialVersionUID = 5902797870154506909L;
        private final String name;
        private String version;

        public OpenSSHExtension(String name) {
            this(name, null);
        }

        public OpenSSHExtension(String name, String version) {
            this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No extension name");
            this.version = version;
        }

        @Override
        public final String getName() {
            return name;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        @Override
        public int hashCode() {
            return Objects.hash(getName(), getVersion());
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

            OpenSSHExtension other = (OpenSSHExtension) obj;
            return Objects.equals(getName(), other.getName())
                    && Objects.equals(getVersion(), other.getVersion());
        }

        @Override
        public OpenSSHExtension clone() {
            try {
                return getClass().cast(super.clone());
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException("Unexpected clone exception " + toString() + ": " + e.getMessage());
            }
        }

        @Override
        public String toString() {
            return getName() + " " + getVersion();
        }
    }

    protected AbstractOpenSSHExtensionParser(String name) {
        super(name);
    }

    @Override
    public OpenSSHExtension parse(byte[] input, int offset, int len) {
        return parse(new String(input, offset, len, StandardCharsets.UTF_8));
    }

    public OpenSSHExtension parse(String version) {
        return new OpenSSHExtension(getName(), version);
    }
}
