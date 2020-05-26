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
package org.apache.sshd.client.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.apache.sshd.client.auth.hostbased.UserAuthHostBasedFactory;
import org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.NamedFactoriesListParseResult;
import org.apache.sshd.common.util.GenericUtils;

/**
 * Provides a centralized location for the default built-in authentication factories
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum BuiltinUserAuthFactories implements NamedFactory<UserAuthFactory> {
    PASSWORD(UserAuthPasswordFactory.INSTANCE),
    PUBLICKEY(UserAuthPublicKeyFactory.INSTANCE),
    KBINTERACTIVE(UserAuthKeyboardInteractiveFactory.INSTANCE),
    HOSTBASED(UserAuthHostBasedFactory.INSTANCE);

    public static final Set<BuiltinUserAuthFactories> VALUES
            = Collections.unmodifiableSet(EnumSet.allOf(BuiltinUserAuthFactories.class));

    private final UserAuthFactory factory;

    BuiltinUserAuthFactories(UserAuthFactory factory) {
        this.factory = Objects.requireNonNull(factory, "No delegate factory instance");
    }

    @Override
    public UserAuthFactory create() {
        return factory;
    }

    @Override
    public String getName() {
        return factory.getName();
    }

    /**
     * @param  name The factory name (case <U>insensitive</U>) - ignored if {@code null}/empty
     * @return      The matching factory instance - {@code null} if no match found
     */
    public static UserAuthFactory fromFactoryName(String name) {
        Factory<UserAuthFactory> factory = NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, VALUES);
        if (factory == null) {
            return null;
        }

        return factory.create();
    }

    /**
     * @param  factories A comma-separated list of factories' names - ignored if {@code null}/empty
     * @return           A {@link ParseResult} containing the successfully parsed factories and the unknown ones.
     *                   <B>Note:</B> it is up to caller to ensure that the lists do not contain duplicates
     */
    public static ParseResult parseFactoriesList(String factories) {
        return parseFactoriesList(GenericUtils.split(factories, ','));
    }

    public static ParseResult parseFactoriesList(String... factories) {
        return parseFactoriesList(
                GenericUtils.isEmpty((Object[]) factories) ? Collections.emptyList() : Arrays.asList(factories));
    }

    public static ParseResult parseFactoriesList(Collection<String> factories) {
        if (GenericUtils.isEmpty(factories)) {
            return ParseResult.EMPTY;
        }

        List<UserAuthFactory> resolved = new ArrayList<>(factories.size());
        List<String> unknown = Collections.emptyList();
        for (String name : factories) {
            UserAuthFactory c = resolveFactory(name);
            if (c != null) {
                resolved.add(c);
            } else {
                // replace the (unmodifiable) empty list with a real one
                if (unknown.isEmpty()) {
                    unknown = new ArrayList<>();
                }
                unknown.add(name);
            }
        }

        return new ParseResult(resolved, unknown);
    }

    public static UserAuthFactory resolveFactory(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        return fromFactoryName(name);
    }

    /**
     * Holds the result of {@link BuiltinUserAuthFactories#parseFactoriesList(String)}
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    public static class ParseResult extends NamedFactoriesListParseResult<UserAuth, UserAuthFactory> {
        public static final ParseResult EMPTY = new ParseResult(Collections.emptyList(), Collections.emptyList());

        public ParseResult(List<UserAuthFactory> parsed, List<String> unsupported) {
            super(parsed, unsupported);
        }
    }
}
