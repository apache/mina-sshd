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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class NumberUtils {
    /**
     * A {@link List} of all the {@link Class} types used to represent the
     * primitive numerical values
     */
    public static final List<Class<?>> NUMERIC_PRIMITIVE_CLASSES =
            Collections.unmodifiableList(Arrays.<Class<?>>asList(
                        Byte.TYPE, Short.TYPE, Integer.TYPE, Long.TYPE,
                        Float.TYPE, Double.TYPE
                    ));

    /**
     * A {@link List} containing all the pure powers of 2 for a {@code long}
     * value. The value at index <I>n</I> is 2 to the power of <I>n</I>
     */
    public static final List<Long> POWERS_OF_TWO =
            Collections.unmodifiableList(new ArrayList<Long>(Long.SIZE) {
                private static final long serialVersionUID = 1L;    // we're not serializing it

                {
                    long value = 1L;
                    for (int power = 0; power < Long.SIZE; power++, value <<= 1) {
                        add(Long.valueOf(value));
                    }
                }
            });

    private NumberUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static boolean isPowerOf2(long value) {
        for (Long l : POWERS_OF_TWO) {
            if (value == l.longValue()) {
                return true;
            }
        }

        return false;
    }

    public static long getNextPowerOf2(long value) {
        long j = 1L;
        while (j < value) {
            j <<= 1;
        }
        return j;
    }

    public static int getNextPowerOf2(int value) {
        int j = 1;
        while (j < value) {
            j <<= 1;
        }
        return j;
    }

    public static int hashCode(long ... values) {
        if (NumberUtils.length(values) <= 0) {
            return 0;
        }

        int hash = hashCode(values[0]);
        for (int index = 1; index < values.length; index++) {
            hash += 31 * hash + hashCode(values[index]);
        }

        return hash;
    }

    public static int hashCode(int ... values) {
        if (NumberUtils.length(values) <= 0) {
            return 0;
        }

        int hash = values[0];
        for (int index = 1; index < values.length; index++) {
            hash += 31 * hash + values[index];
        }

        return hash;
    }

    // TODO in JDK-8 use Long.hashCode(long)
    public static int hashCode(long value) {
        return (int) (value ^ (value >>> 32));
    }

    /**
     * @param clazz The {@link Class} to examine - ignored if {@code null}
     * @return If the class is a {@link Number} or one of the primitive numerical types
     * @see #NUMERIC_PRIMITIVE_CLASSES
     */
    public static boolean isNumericClass(Class<?> clazz) {
        if (clazz == null) {
            return false;
        }

        // turns out that the primitive types are not assignable to Number
        if (Number.class.isAssignableFrom(clazz)) {
            return true;
        }

        return NUMERIC_PRIMITIVE_CLASSES.indexOf(clazz) >= 0;
    }

    /**
     * Converts a {@link Number} into an {@link Integer} if not already such
     *
     * @param n The {@link Number} - ignored if {@code null}
     * @return The equivalent {@link Integer} value
     */
    public static Integer toInteger(Number n) {
        if (n == null) {
            return null;
        } else if (n instanceof Integer) {
            return (Integer) n;
        } else {
            return Integer.valueOf(n.intValue());
        }
    }

    public static String join(CharSequence separator, long ... values) {
        if (NumberUtils.isEmpty(values)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(values.length * Byte.SIZE);
        for (long v : values) {
            if (sb.length() > 0) {
                sb.append(separator);
            }
            sb.append(v);
        }

        return sb.toString();
    }

    public static String join(char separator, long ... values) {
        if (NumberUtils.isEmpty(values)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(values.length * Byte.SIZE);
        for (long v : values) {
            if (sb.length() > 0) {
                sb.append(separator);
            }
            sb.append(v);
        }

        return sb.toString();
    }

    public static String join(CharSequence separator, boolean unsigned, byte ... values) {
        if (NumberUtils.isEmpty(values)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(values.length * Byte.SIZE);
        for (byte v : values) {
            if (sb.length() > 0) {
                sb.append(separator);
            }
            sb.append(unsigned ? (v & 0xFF) : v);
        }

        return sb.toString();
    }

    public static String join(char separator, boolean unsigned, byte ... values) {
        if (NumberUtils.isEmpty(values)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(values.length * Byte.SIZE);
        for (byte v : values) {
            if (sb.length() > 0) {
                sb.append(separator);
            }
            sb.append(unsigned ? (v & 0xFF) : v);
        }

        return sb.toString();
    }

    public static String join(CharSequence separator, int ... values) {
        if (NumberUtils.isEmpty(values)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(values.length * Byte.SIZE);
        for (int v : values) {
            if (sb.length() > 0) {
                sb.append(separator);
            }
            sb.append(v);
        }

        return sb.toString();
    }

    public static String join(char separator, int ... values) {
        if (NumberUtils.isEmpty(values)) {
            return "";
        }

        StringBuilder sb = new StringBuilder(values.length * Byte.SIZE);
        for (int v : values) {
            if (sb.length() > 0) {
                sb.append(separator);
            }
            sb.append(v);
        }

        return sb.toString();
    }

    public static boolean isEmpty(byte[] a) {
        return NumberUtils.length(a) <= 0;
    }

    public static boolean isEmpty(int[] a) {
        return NumberUtils.length(a) <= 0;
    }

    public static boolean isEmpty(long[] a) {
        return NumberUtils.length(a) <= 0;
    }

    public static int length(byte... a) {
        return a == null ? 0 : a.length;
    }

    public static int length(int... a) {
        return a == null ? 0 : a.length;
    }

    public static int length(long... a) {
        return a == null ? 0 : a.length;
    }

    public static List<Integer> asList(int ... values) {
        int len = length(values);
        if (len <= 0) {
            return Collections.emptyList();
        }

        List<Integer> l = new ArrayList<>(len);
        for (int v : values) {
            l.add(Integer.valueOf(v));
        }

        return l;
    }

    /**
     * Checks if optional sign and all others are '0'-'9'
     * @param cs The {@link CharSequence} to check
     * @return {@code true} if valid integer number
     */
    public static boolean isIntegerNumber(CharSequence cs) {
        if (GenericUtils.isEmpty(cs)) {
            return false;
        }

        for (int index = 0; index < cs.length(); index++) {
            char c = cs.charAt(0);
            if ((c >= '0') && (c <= '9')) {
                continue;
            }

            if ((c == '+') || (c == '-')) {
                if (index == 0) {
                    continue;
                }
            }

            return false;
        }

        return true;
    }
}
