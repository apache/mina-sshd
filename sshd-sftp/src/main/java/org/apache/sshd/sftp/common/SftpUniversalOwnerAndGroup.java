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

package org.apache.sshd.sftp.common;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import org.apache.sshd.common.NamedResource;

/**
 * Some universal identifiers used in owner and/or group specification strings
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://tools.ietf.org/html/draft-ietf-secsh-filexfer-04#page-12">SFTP ACL</A>
 */
public enum SftpUniversalOwnerAndGroup implements NamedResource {
    Owner, // The owner of the file.
    Group, // The group associated with the file.
    Everyone, // The world.
    Interactive, // Accessed from an interactive terminal.
    Network, // Accessed via the network.
    Dialup, // Accessed as a dialup user to the server.
    Batch, // Accessed from a batch job.
    Anonymous, // Accessed without any authentication.
    Authenticated, // Any authenticated user (opposite of ANONYMOUS).
    Service; // Access from a system service.

    public static final Set<SftpUniversalOwnerAndGroup> VALUES
            = Collections.unmodifiableSet(EnumSet.allOf(SftpUniversalOwnerAndGroup.class));

    private final String name;

    SftpUniversalOwnerAndGroup() {
        name = name().toUpperCase() + "@";
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return getName();
    }

    public static SftpUniversalOwnerAndGroup fromName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }
}
