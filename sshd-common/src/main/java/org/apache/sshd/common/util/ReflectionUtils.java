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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class ReflectionUtils {
    public static final Function<Field, String> FIELD_NAME_EXTRACTOR = f -> (f == null) ? null : f.getName();

    private ReflectionUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static Collection<Field> getMatchingFields(Class<?> clazz, Predicate<? super Field> acceptor) {
        return GenericUtils.selectMatchingMembers(acceptor, clazz.getFields());
    }

    public static Collection<Field> getMatchingDeclaredFields(Class<?> clazz, Predicate<? super Field> acceptor) {
        return GenericUtils.selectMatchingMembers(acceptor, clazz.getDeclaredFields());
    }

    public static boolean isClassAvailable(ClassLoader cl, String className) {
        try {
            cl.loadClass(className);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static Object newInstance(Class<?> clazz) throws ReflectiveOperationException {
        return newInstance(clazz, Object.class);
    }

    @SuppressWarnings("checkstyle:ThrowsCount")
    public static <T> T newInstance(Class<?> clazz, Class<? extends T> castType) throws ReflectiveOperationException {
        Constructor<?> ctor = clazz.getDeclaredConstructor();
        Object instance = ctor.newInstance();
        return castType.cast(instance);
    }
}
