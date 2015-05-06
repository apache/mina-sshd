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
public class ValidateUtils {
    public static final <T> T checkNotNull(T t, String message, Object ... args) {
        if (t == null) {
            throw new IllegalStateException(String.format(message, args));
        }
        return t;
    }

    public static final String checkNotNullAndNotEmpty(String t, String message, Object ... args) {
        t = checkNotNull(t, message, args).trim();
        if (t.isEmpty()) {
            throw new IllegalArgumentException(String.format(message, args));
        }
        return t;
    }

    public static final <K,V,M extends Map<K,V>> M checkNotNullAndNotEmpty(M t, String message, Object ... args) {
        t = checkNotNull(t, message, args);
        if (GenericUtils.size(t) <= 0) {
            throw new IllegalArgumentException(String.format(message, args));
        }
        
        return t;
    }

    public static final <T,C extends Collection<T>> C checkNotNullAndNotEmpty(C t, String message, Object ... args) {
        t = checkNotNull(t, message, args);
        if (GenericUtils.size(t) <= 0) {
            throw new IllegalArgumentException(String.format(message, args));
        }
        
        return t;
    }

    public static final <T> T[] checkNotNullAndNotEmpty(T[] t, String message, Object ... args) {
        t = checkNotNull(t, message, args);
        if (GenericUtils.length(t) <= 0) {
            throw new IllegalArgumentException(String.format(message, t, args));
        }
        return t;
    }
}
