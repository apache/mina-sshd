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

package org.apache.sshd.common.config.keys.loader.openssh.kdf;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.loader.openssh.OpenSSHKdfOptions;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.buffer.BufferUtils;

/**
 * Generic options
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class RawKdfOptions implements OpenSSHKdfOptions {
    private String name;
    private byte[] options;

    public RawKdfOptions() {
        super();
    }

    @Override
    public void initialize(String name, byte[] kdfOptions) throws IOException {
        setName(name);
        setOptions(options);
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getOptions() {
        return NumberUtils.emptyIfNull(options);
    }

    public void setOptions(byte[] options) {
        this.options = NumberUtils.emptyIfNull(options);
    }

    @Override
    public boolean isEncrypted() {
        return !IS_NONE_KDF.test(getName());
    }

    @Override
    public byte[] decodePrivateKeyBytes(
            SessionContext session, NamedResource resourceKey, String cipherName, byte[] privateDataBytes, String password)
            throws IOException, GeneralSecurityException {
        throw new NoSuchAlgorithmException("Unsupported KDF algorithm (" + getName() + ")");
    }

    @Override
    public int hashCode() {
        return GenericUtils.hashCode(getName(), Boolean.FALSE) + Arrays.hashCode(getOptions());
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

        RawKdfOptions other = (RawKdfOptions) obj;
        return (GenericUtils.safeCompare(getName(), other.getName(), false) == 0)
                && Arrays.equals(getOptions(), other.getOptions());
    }

    @Override
    public String toString() {
        return getName() + ": options=" + BufferUtils.toHex(':', getOptions());
    }
}
