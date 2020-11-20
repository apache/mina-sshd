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

package org.apache.sshd.common.signature;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * Manage the list of named factories for <code>Signature</code>.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SignatureFactoriesManager extends SignatureFactoriesHolder {
    void setSignatureFactories(List<NamedFactory<Signature>> factories);

    default void setSignatureFactoriesNameList(String names) {
        setSignatureFactoriesNames(GenericUtils.split(names, ','));
    }

    default void setSignatureFactoriesNames(String... names) {
        setSignatureFactoriesNames(GenericUtils.isEmpty((Object[]) names) ? Collections.emptyList() : Arrays.asList(names));
    }

    default void setSignatureFactoriesNames(Collection<String> names) {
        BuiltinSignatures.ParseResult result = BuiltinSignatures.parseSignatureList(names);
        @SuppressWarnings({ "rawtypes", "unchecked" })
        List<NamedFactory<Signature>> factories = (List) ValidateUtils.checkNotNullAndNotEmpty(result.getParsedFactories(),
                "No supported signature factories: %s", names);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(GenericUtils.isEmpty(unsupported), "Unsupported signature factories found: %s", unsupported);
        setSignatureFactories(factories);
    }

    /**
     * Attempts to use the primary manager's signature factories if not {@code null}/empty, otherwise uses the secondary
     * ones (regardless of whether there are any...)
     *
     * @param  primary   The primary {@link SignatureFactoriesManager}
     * @param  secondary The secondary {@link SignatureFactoriesManager}
     * @return           The resolved signature factories - may be {@code null}/empty
     * @see              #getSignatureFactories(SignatureFactoriesManager)
     */
    static List<NamedFactory<Signature>> resolveSignatureFactories(
            SignatureFactoriesManager primary, SignatureFactoriesManager secondary) {
        List<NamedFactory<Signature>> factories = getSignatureFactories(primary);
        return GenericUtils.isEmpty(factories) ? getSignatureFactories(secondary) : factories;
    }

    /**
     * @param  manager The {@link SignatureFactoriesManager} instance - ignored if {@code null}
     * @return         The associated list of named <code>Signature</code> factories or {@code null} if no manager
     *                 instance
     */
    static List<NamedFactory<Signature>> getSignatureFactories(SignatureFactoriesManager manager) {
        return (manager == null) ? null : manager.getSignatureFactories();
    }
}
