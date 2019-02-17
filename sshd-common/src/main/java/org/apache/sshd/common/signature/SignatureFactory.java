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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.sshd.common.BuiltinFactory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SignatureFactory extends BuiltinFactory<Signature> {
    /**
     * @param provided The provided signature key types
     * @param factories The available signature factories
     * @return A {@link List} of the matching available factories names
     * that are also listed as provided ones - in the same <U>order</U>
     * of preference as they appear in the available listing. May be
     * empty if no provided signature key types, or no available ones
     * or no match found.
     * @see #resolveSignatureFactoryNamesProposal(Iterable, Collection)
     */
    static List<String> resolveSignatureFactoriesProposal(
            Iterable<String> provided, Collection<? extends NamedFactory<Signature>> factories) {
        return resolveSignatureFactoryNamesProposal(provided, NamedResource.getNameList(factories));
    }

    /**
     * @param provided The provided signature key types
     * @param available The available signature factories names
     * @return A {@link List} of the matching available factories names
     * that are also listed as provided ones - in the same <U>order</U>
     * of preference as they appear in the available listing. May be
     * empty if no provided signature key types, or no available ones
     * or no match found.
     */
    static List<String> resolveSignatureFactoryNamesProposal(
            Iterable<String> provided, Collection<String> available) {
        if ((provided == null) || GenericUtils.isEmpty(available)) {
            return Collections.emptyList();
        }

        // We want to preserve the original available order as it indicates the preference
        Set<String> providedKeys = new HashSet<>();
        for (String providedType : provided) {
            Collection<String> equivTypes =
                KeyUtils.getAllEquivalentKeyTypes(providedType);
            providedKeys.addAll(equivTypes);
        }

        if (GenericUtils.isEmpty(providedKeys)) {
            return Collections.emptyList();
        }

        List<String> supported = new ArrayList<>(available);
        for (int index = 0; index < supported.size(); index++) {
            String kt = supported.get(index);
            if (!providedKeys.contains(kt)) {
                supported.remove(index);
                index--;    // compensate for auto-increment
            }
        }

        return supported;
    }
}

