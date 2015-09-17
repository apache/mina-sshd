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

package org.apache.sshd.server.auth.keyboard;

import java.io.Serializable;
import java.util.Objects;

import org.apache.sshd.common.util.buffer.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class PromptEntry implements Serializable, Cloneable {
    private static final long serialVersionUID = 8206049800536373640L;

    private String prompt;
    private boolean echo;

    public PromptEntry() {
        super();
    }

    public PromptEntry(String prompt, boolean echo) {
        this.prompt = prompt;
        this.echo = echo;
    }

    public String getPrompt() {
        return prompt;
    }

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    public boolean isEcho() {
        return echo;
    }

    public void setEcho(boolean echo) {
        this.echo = echo;
    }

    public <B extends Buffer> B append(B buffer) {
        buffer.putString(getPrompt());
        buffer.putBoolean(isEcho());
        return buffer;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getPrompt()) + (isEcho() ? 1 : 0);
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

        PromptEntry other = (PromptEntry) obj;
        return Objects.equals(getPrompt(), other.getPrompt()) && (isEcho() == other.isEcho());
    }

    @Override
    public PromptEntry clone() {
        try {
            return getClass().cast(super.clone());
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException("Failed to clone " + toString() + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        return getPrompt() + "(echo=" + isEcho() + ")";
    }
}
