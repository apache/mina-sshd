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

package org.apache.sshd.client.subsystem.sftp;

import java.util.Collection;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.NumberUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SftpVersionSelector {

    /**
     * An {@link SftpVersionSelector} that returns the current version
     */
    SftpVersionSelector CURRENT = new SftpVersionSelector() {
        @Override
        public int selectVersion(int current, List<Integer> available) {
            return current;
        }
    };

    /**
     * An {@link SftpVersionSelector} that returns the maximum available version
     */
    SftpVersionSelector MAXIMUM = new SftpVersionSelector() {
        @Override
        public int selectVersion(int current, List<Integer> available) {
            int candidate = current;
            if (GenericUtils.size(available) > 0) {
                for (Number version : available) {
                    if (candidate < version.intValue()) {
                        candidate = version.intValue();
                    }
                }
            }
            return candidate;
        }
    };

    /**
     * An {@link SftpVersionSelector} that returns the maximum available version
     */
    SftpVersionSelector MINIMUM = new SftpVersionSelector() {
        @Override
        public int selectVersion(int current, List<Integer> available) {
            int candidate = current;
            if (GenericUtils.size(available) > 0) {
                for (Number version : available) {
                    if (candidate > version.intValue()) {
                        candidate = version.intValue();
                    }
                }
            }
            return candidate;
        }
    };

    /**
     * @param current   The current version negotiated with the server
     * @param available Extra versions available - may be empty and/or contain
     *                  only the current one
     * @return The new requested version - if same as current, then nothing is done
     */
    int selectVersion(int current, List<Integer> available);

    /**
     * Utility class to help using {@link SftpVersionSelector}s
     */
    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        /**
         * Creates a selector the always returns the requested (fixed version) regardless
         * of what the current or reported available versions are. If the requested version
         * is not reported as available then an exception will be eventually thrown by the
         * client during re-negotiation phase.
         *
         * @param version The requested version
         * @return The {@link SftpVersionSelector}
         */
        public static SftpVersionSelector fixedVersionSelector(final int version) {
            return new SftpVersionSelector() {
                @Override
                public int selectVersion(int current, List<Integer> available) {
                    return version;
                }
            };
        }

        /**
         * Selects a version in order of preference - if none of the preferred
         * versions is listed as available then an exception is thrown when the
         * {@link SftpVersionSelector#selectVersion(int, List)} method is invoked
         *
         * @param preferred The preferred versions in decreasing order of
         * preference (i.e., most preferred is 1st) - may not be {@code null}/empty
         * @return A {@link SftpVersionSelector} that attempts to select
         * the most preferred version that is also listed as available.
         */
        public static SftpVersionSelector preferredVersionSelector(final int ... preferred) {
            return preferredVersionSelector(NumberUtils.asList(preferred));

        }

        /**
         * Selects a version in order of preference - if none of the preferred
         * versions is listed as available then an exception is thrown when the
         * {@link SftpVersionSelector#selectVersion(int, List)} method is invoked
         *
         * @param preferred The preferred versions in decreasing order of
         * preference (i.e., most preferred is 1st)
         * @return A {@link SftpVersionSelector} that attempts to select
         * the most preferred version that is also listed as available.
         */
        public static SftpVersionSelector preferredVersionSelector(final Iterable<? extends Number> preferred) {
            if (preferred instanceof Collection<?>) {
                ValidateUtils.checkNotNullAndNotEmpty((Collection<?>) preferred, "Empty preferred versions");
            } else {
                ValidateUtils.checkNotNull(preferred, "No preferred versions");
            }

            return new SftpVersionSelector() {
                @Override
                public int selectVersion(int current, List<Integer> available) {
                    for (Number prefValue : preferred) {
                        int version = prefValue.intValue();
                        if (version == current) {
                            return version;
                        }

                        for (Integer avail : available) {
                            if (version == avail.intValue()) {
                                return version;
                            }
                        }
                    }

                    throw new IllegalStateException("Preferred versions (" + preferred + ") not available: " + available);
                }
            };
        }
    }
}
