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

package org.apache.sshd.common.auth;

import java.util.Objects;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BasicCredentialsImpl implements MutableBasicCredentials, Cloneable {
    private String username;
    private String password;

    public BasicCredentialsImpl() {
        super();
    }

    public BasicCredentialsImpl(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public BasicCredentialsImpl clone() {
        try {
            return getClass().cast(super.clone());
        } catch (CloneNotSupportedException e) {
            throw new UnsupportedOperationException("Unexpected failure to clone: " + e.getMessage(), e);
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(getUsername(), getPassword());
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

        BasicCredentialsImpl other = (BasicCredentialsImpl) obj;
        return Objects.equals(getUsername(), other.getUsername())
                && Objects.equals(getPassword(), other.getPassword());
    }

    // NOTE: do not implement 'toString' on purpose to avoid inadvertent logging of contents
}
