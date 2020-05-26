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

package org.apache.sshd.client.config.hosts;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Available digesters for known hosts entries
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum KnownHostDigest implements NamedFactory<Mac> {
    SHA1("1", BuiltinMacs.hmacsha1);

    public static final Set<KnownHostDigest> VALUES = Collections.unmodifiableSet(EnumSet.allOf(KnownHostDigest.class));

    private final String name;
    private final Factory<Mac> factory;

    KnownHostDigest(String name, Factory<Mac> factory) {
        this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No name");
        this.factory = Objects.requireNonNull(factory, "No factory");
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Mac create() {
        return factory.create();
    }

    public static KnownHostDigest fromName(String name) {
        return NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
    }
}
