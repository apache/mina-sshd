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
package org.apache.sshd.common.config.keys.impl;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.NavigableSet;
import java.util.Objects;

import org.apache.sshd.common.config.keys.IdentityResourceLoader;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;

/**
 * @param  <PUB> Generic public key type
 * @param  <PRV> Generic private key type
 * @author       <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractIdentityResourceLoader<PUB extends PublicKey, PRV extends PrivateKey>
        extends AbstractLoggingBean
        implements IdentityResourceLoader<PUB, PRV> {
    private final Class<PUB> pubType;
    private final Class<PRV> prvType;
    private final NavigableSet<String> types;

    protected AbstractIdentityResourceLoader(
                                             Class<PUB> pubType, Class<PRV> prvType, Collection<String> keyTypes) {
        this.pubType = Objects.requireNonNull(pubType, "No public key type specified");
        this.prvType = Objects.requireNonNull(prvType, "No private key type specified");
        this.types = Collections.unmodifiableNavigableSet(
                GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER,
                        ValidateUtils.checkNotNullAndNotEmpty(keyTypes, "No key type names provided")));
    }

    @Override
    public final Class<PUB> getPublicKeyType() {
        return pubType;
    }

    @Override
    public final Class<PRV> getPrivateKeyType() {
        return prvType;
    }

    @Override
    public NavigableSet<String> getSupportedKeyTypes() {
        return types;
    }
}
