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

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ScpDirEndCommandDetails extends AbstractScpCommandDetails {
    public static final char COMMAND_NAME = 'E';
    public static final String HEADER = "E";

    public static final ScpDirEndCommandDetails INSTANCE = new ScpDirEndCommandDetails();

    public ScpDirEndCommandDetails() {
        super(COMMAND_NAME);
    }

    public ScpDirEndCommandDetails(String header) {
        super(COMMAND_NAME);
        if (!HEADER.equals(header)) {
            throw new IllegalArgumentException("Mismatched header - expected '" + HEADER + "' but got '" + header + "'");
        }
    }

    @Override
    public String toHeader() {
        return HEADER;
    }

    @Override
    public int hashCode() {
        return HEADER.hashCode();
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

        // All ScpDirEndCommandDetails are equal to each other
        return true;
    }

    public static ScpDirEndCommandDetails parse(String header) {
        if (GenericUtils.isEmpty(header)) {
            return null;
        }

        if (HEADER.equals(header)) {
            return INSTANCE;
        }

        throw new IllegalArgumentException("Invalid header: " + header);
    }
}
