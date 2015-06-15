/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.sshd.common.util;

import java.util.Collection;
import java.util.Map;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class ValidateUtils {
    private ValidateUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static final <T> T checkNotNull(T t, String message, Object arg) {
        if (t == null) {
            throwIllegalArgumentException(message, arg);
        }
        
        return t;
    }

    public static final <T> T checkNotNull(T t, String message, Object ... args) {
        checkTrue(t != null, message, args);
        return t;
    }

    public static final String checkNotNullAndNotEmpty(String t, String message, Object ... args) {
        t = checkNotNull(t, message, args).trim();
        checkTrue(GenericUtils.length(t) > 0, message, args);
        return t;
    }

    public static final <K,V,M extends Map<K,V>> M checkNotNullAndNotEmpty(M t, String message, Object ... args) {
        t = checkNotNull(t, message, args);
        checkTrue(GenericUtils.size(t) > 0, message, args);
        return t;
    }

    public static final <T,C extends Collection<T>> C checkNotNullAndNotEmpty(C t, String message, Object ... args) {
        t = checkNotNull(t, message, args);
        checkTrue(GenericUtils.size(t) > 0, message, args);
        return t;
    }

    public static final <T> T[] checkNotNullAndNotEmpty(T[] t, String message, Object ... args) {
        t = checkNotNull(t, message, args);
        checkTrue(GenericUtils.length(t) > 0, message, args);
        return t;
    }

    public static final void checkTrue(boolean flag, String message, long arg) {
        if (!flag) {
            throwIllegalArgumentException(message, Long.valueOf(arg));
        }
    }

    public static final void checkTrue(boolean flag, String message, Object arg) {
        if (!flag) {
            throwIllegalArgumentException(message, arg);
        }
    }

    public static final void checkTrue(boolean flag, String message, Object ... args) {
        if (!flag) {
            throwIllegalArgumentException(message, args);
        }
    }
    
    public static final void throwIllegalArgumentException(String message, Object ... args) {
        throw new IllegalArgumentException(String.format(message, args));
    }
}
