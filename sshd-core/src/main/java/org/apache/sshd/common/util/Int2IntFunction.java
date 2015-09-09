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

package org.apache.sshd.common.util;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Int2IntFunction {

    /**
     * An {@link Int2IntFunction} that returns same value as input
     */
    Int2IntFunction IDENTITY = new Int2IntFunction() {
        @Override
        public int apply(int value) {
            return value;
        }
    };

    /**
     * @param value Argument
     * @return Function result
     */
    int apply(int value);

    // CHECKSTYLE:OFF
    final class Utils {
    // CHECKSTYLE:ON

        private Utils() {
            throw new UnsupportedOperationException("No instance allowed");
        }

        public static Int2IntFunction sub(int delta) {
            return add(0 - delta);
        }

        public static Int2IntFunction add(final int delta) {
            if (delta == 0) {
                return IDENTITY;
            } else {
                return new Int2IntFunction() {
                    @Override
                    public int apply(int value) {
                        return value + delta;
                    }
                };
            }
        }

        public static Int2IntFunction mul(final int factor) {
            if (factor == 1) {
                return IDENTITY;
            } else {
                return new Int2IntFunction() {
                    @Override
                    public int apply(int value) {
                        return value * factor;
                    }
                };
            }
        }

        public static Int2IntFunction div(final int factor) {
            if (factor == 1) {
                return IDENTITY;
            } else {
                ValidateUtils.checkTrue(factor != 0, "Zero division factor");
                return new Int2IntFunction() {
                    @Override
                    public int apply(int value) {
                        return value / factor;
                    }
                };
            }
        }
    }
}
