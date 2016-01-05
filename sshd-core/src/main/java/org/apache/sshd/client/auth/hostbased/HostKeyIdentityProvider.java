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

package org.apache.sshd.client.auth.hostbased;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Pair;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface HostKeyIdentityProvider {
    /**
     * @return The host keys as a {@link Pair} of key + certificates (which can be {@code null}/empty)
     */
    Iterable<Pair<KeyPair, List<X509Certificate>>> loadHostKeys();

    /**
     * A helper class for key identity provider related operations
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON
        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        public static Iterator<Pair<KeyPair, List<X509Certificate>>> iteratorOf(HostKeyIdentityProvider provider) {
            return GenericUtils.iteratorOf((provider == null) ? null : provider.loadHostKeys());
        }

        public static HostKeyIdentityProvider wrap(KeyPair ... pairs) {
            return wrap(GenericUtils.isEmpty(pairs) ? Collections.<KeyPair>emptyList() : Arrays.asList(pairs));
        }

        public static HostKeyIdentityProvider wrap(final Iterable<? extends KeyPair> pairs) {
            return new HostKeyIdentityProvider() {
                @Override
                public Iterable<Pair<KeyPair, List<X509Certificate>>> loadHostKeys() {
                    return new Iterable<Pair<KeyPair, List<X509Certificate>>>() {
                        @Override
                        public Iterator<Pair<KeyPair, List<X509Certificate>>> iterator() {
                            final Iterator<? extends KeyPair> iter = GenericUtils.iteratorOf(pairs);
                            return new Iterator<Pair<KeyPair, List<X509Certificate>>>() {

                                @Override
                                public boolean hasNext() {
                                    return iter.hasNext();
                                }

                                @Override
                                public Pair<KeyPair, List<X509Certificate>> next() {
                                    KeyPair kp = iter.next();
                                    return new Pair<KeyPair, List<X509Certificate>>(kp, Collections.<X509Certificate>emptyList());
                                }

                                @Override
                                public void remove() {
                                    throw new UnsupportedOperationException("No removal allowed");
                                }
                            };
                        }
                    };
                }

            };
        }
    }
}
