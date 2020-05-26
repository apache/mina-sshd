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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @param  <S> Type of session being managed
 * @param  <M> Type of {@code UserAuth} being used
 * @param  <F> Type of user authentication mechanism factory
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface UserAuthFactoriesManager<
        S extends SessionContext,
        M extends UserAuthInstance<S>, F extends UserAuthMethodFactory<S, M>> {
    /**
     * Retrieve the list of named factories for <code>UserAuth</code> objects.
     *
     * @return a list of named <code>UserAuth</code> factories, never {@code null}/empty
     */
    List<F> getUserAuthFactories();

    default String getUserAuthFactoriesNameList() {
        return NamedResource.getNames(getUserAuthFactories());
    }

    default List<String> getUserAuthFactoriesNames() {
        return NamedResource.getNameList(getUserAuthFactories());
    }

    void setUserAuthFactories(List<F> userAuthFactories);

    default void setUserAuthFactoriesNameList(String names) {
        setUserAuthFactoriesNames(GenericUtils.split(names, ','));
    }

    default void setUserAuthFactoriesNames(String... names) {
        setUserAuthFactoriesNames(
                GenericUtils.isEmpty((Object[]) names)
                        ? Collections.emptyList()
                        : Arrays.asList(names));
    }

    void setUserAuthFactoriesNames(Collection<String> names);
}
