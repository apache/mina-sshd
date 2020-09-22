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

package org.apache.sshd.sftp.client;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface SftpVersionSelector {
    /**
     * An {@link SftpVersionSelector} that returns the current version
     */
    NamedVersionSelector CURRENT = new NamedVersionSelector("CURRENT", (session, initial, current, available) -> current);

    /**
     * An {@link SftpVersionSelector} that returns the maximum available version
     */
    NamedVersionSelector MAXIMUM = new NamedVersionSelector(
            "MAXIMUM",
            (session, initial, current, available) -> GenericUtils.stream(available).mapToInt(Integer::intValue).max()
                    .orElse(current));

    /**
     * An {@link SftpVersionSelector} that returns the minimum available version
     */
    NamedVersionSelector MINIMUM = new NamedVersionSelector(
            "MINIMUM",
            (session, initial, current, available) -> GenericUtils.stream(available).mapToInt(Integer::intValue).min()
                    .orElse(current));

    /**
     * @param  session   The {@link ClientSession} through which the SFTP connection is made
     * @param  initial   If {@code true} then this is the initial version sent via {@code SSH_FXP_INIT} otherwise it is
     *                   a re-negotiation.
     * @param  current   The current version negotiated with the server
     * @param  available Extra versions available - may be empty and/or contain only the current one
     * @return           The new requested version - if same as current, then nothing is done
     */
    int selectVersion(ClientSession session, boolean initial, int current, List<Integer> available);

    /**
     * Creates a selector the always returns the requested (fixed version) regardless of what the current or reported
     * available versions are. If the requested version is not reported as available then an exception will be
     * eventually thrown by the client during re-negotiation phase.
     *
     * @param  version The requested version
     * @return         The {@link NamedVersionSelector} wrapping the requested version
     */
    static NamedVersionSelector fixedVersionSelector(int version) {
        return new NamedVersionSelector(Integer.toString(version), (session, initial, current, available) -> version);
    }

    /**
     * Selects a version in order of preference - if none of the preferred versions is listed as available then an
     * exception is thrown when the {@link SftpVersionSelector#selectVersion(ClientSession, boolean, int, List)} method
     * is invoked
     *
     * @param  preferred The preferred versions in decreasing order of preference (i.e., most preferred is 1st) - may
     *                   not be {@code null}/empty
     * @return           A {@link NamedVersionSelector} that attempts to select the most preferred version that is also
     *                   listed as available.
     */
    static NamedVersionSelector preferredVersionSelector(int... preferred) {
        return preferredVersionSelector(NumberUtils.asList(preferred));
    }

    /**
     * Selects a version in order of preference - if none of the preferred versions is listed as available then an
     * exception is thrown when the {@link SftpVersionSelector#selectVersion(ClientSession, boolean, int, List)} method
     * is invoked
     *
     * @param  preferred The preferred versions in decreasing order of preference (i.e., most preferred is 1st)
     * @return           A {@link NamedVersionSelector} that attempts to select the most preferred version that is also
     *                   listed as available.
     */
    static NamedVersionSelector preferredVersionSelector(Iterable<? extends Number> preferred) {
        ValidateUtils.checkNotNullAndNotEmpty((Collection<?>) preferred, "Empty preferred versions");
        return new NamedVersionSelector(
                GenericUtils.join(preferred, ','),
                (session, initial, current, available) -> StreamSupport.stream(preferred.spliterator(), false)
                        .mapToInt(Number::intValue)
                        .filter(v -> (v == current) || available.contains(v))
                        .findFirst()
                        .orElseThrow(() -> new IllegalStateException(
                                "Preferred versions (" + preferred + ") not available: " + available)));
    }

    /**
     * Parses the input string to see if it matches one of the &quot;known&quot; selectors names (case insensitive). If
     * not, then checks if it is a single number and uses it as a {@link #fixedVersionSelector(int) fixed} version.
     * Otherwise, assumes a comma separated list of versions in preferred order.
     *
     * @param  selector The selector value - if {@code null}/empty then returns {@link #CURRENT}
     * @return          Parsed {@link NamedVersionSelector}
     */
    static NamedVersionSelector resolveVersionSelector(String selector) {
        if (GenericUtils.isEmpty(selector)) {
            return SftpVersionSelector.CURRENT;
        } else if (selector.equalsIgnoreCase(SftpVersionSelector.CURRENT.getName())) {
            return SftpVersionSelector.CURRENT;
        } else if (selector.equalsIgnoreCase(SftpVersionSelector.MINIMUM.getName())) {
            return SftpVersionSelector.MINIMUM;
        } else if (selector.equalsIgnoreCase(SftpVersionSelector.MAXIMUM.getName())) {
            return SftpVersionSelector.MAXIMUM;
        } else if (NumberUtils.isIntegerNumber(selector)) {
            return SftpVersionSelector.fixedVersionSelector(Integer.parseInt(selector));
        } else {
            String[] preferred = GenericUtils.split(selector, ',');
            int[] prefs = Stream.of(preferred).mapToInt(Integer::parseInt).toArray();
            return SftpVersionSelector.preferredVersionSelector(prefs);
        }
    }

    /**
     * Wraps a {@link SftpVersionSelector} and assigns it a name. <B>Note:</B> {@link NamedVersionSelector} are
     * considered equal if they are assigned the same name - case <U>insensitive</U>
     *
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     */
    class NamedVersionSelector implements SftpVersionSelector, NamedResource {
        protected final SftpVersionSelector selector;

        private final String name;

        public NamedVersionSelector(String name, SftpVersionSelector selector) {
            this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No name provided");
            this.selector = Objects.requireNonNull(selector, "No delegate selector provided");
        }

        @Override
        public int selectVersion(ClientSession session, boolean initial, int current, List<Integer> available) {
            return selector.selectVersion(session, initial, current, available);
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public int hashCode() {
            return GenericUtils.hashCode(getName(), Boolean.TRUE);
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

            return NamedResource.safeCompareByName(this, (NamedVersionSelector) obj, false) == 0;
        }

        @Override
        public String toString() {
            return getName();
        }
    }
}
