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
package org.apache.sshd.common.util.security;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.Callable;

/**
 * A wrapper around AccessController so that our code can work on JREs that do or do not have it.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class PrivilegedOperations {

    private PrivilegedOperations() {
        throw new IllegalStateException("No instantiation of class PrivilegedOperations");
    }

    public static class PrivilegeException extends Exception {

        private static final long serialVersionUID = 945792544549913161L;

        PrivilegeException(Throwable cause) {
            super(cause);
        }
    }

    public static ThreadGroup getPrivilegedThreadGroup() {
        if (HasSecurity.withSecurityManager()) {
            return HasSecurity.getPrivilegedThreadGroup();
        }
        return null;
    }

    public static void doPrivileged(Runnable action) {
        if (HasSecurity.isAvailable()) {
            HasSecurity.doPrivileged(action);
        } else {
            action.run();
        }
    }

    public static <T> T doPrivileged(Callable<? extends T> action) throws PrivilegeException {
        if (HasSecurity.isAvailable()) {
            return HasSecurity.doPrivileged(action);
        }
        try {
            return action.call();
        } catch (Exception e) {
            throw new PrivilegeException(e);
        }
    }

    public static <T> T doPrivilegedConditional(Callable<? extends T> action) throws PrivilegeException {
        if (HasSecurity.withSecurityManager()) {
            return doPrivileged(action);
        }
        try {
            return action.call();
        } catch (Exception e) {
            throw new PrivilegeException(e);
        }
    }

    private static final class HasSecurity {

        private static final boolean HAS_SECURITY_MANAGER = haveSecurityManager();

        private static final boolean HAS_ACCESS_CONTROLLER = haveAccessController();

        private HasSecurity() {
            throw new IllegalStateException("No instantiation of class PrivilegedOperations$HasSecurity");
        }

        private static boolean haveSecurityManager() {
            try {
                Method m = System.class.getDeclaredMethod("getSecurityManager");
                if (m == null) {
                    return false;
                }
                return m.invoke(null) != null;
            } catch (Throwable t) {
                return false;
            }
        }

        private static boolean haveAccessController() {
            try {
                HasSecurity.class.getClassLoader().loadClass("java.security.AccessController");
                return true;
            } catch (Throwable t) {
                return false;
            }
        }

        static boolean withSecurityManager() {
            return HAS_SECURITY_MANAGER;
        }

        static boolean isAvailable() {
            return HAS_ACCESS_CONTROLLER;
        }

        static ThreadGroup getPrivilegedThreadGroup() {
            return System.getSecurityManager().getThreadGroup();
        }

        static void doPrivileged(Runnable action) {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                action.run();
                return null;
            });
        }

        static <T> T doPrivileged(Callable<? extends T> action) throws PrivilegeException {
            try {
                return AccessController.doPrivileged(new PrivilegedExceptionAction<T>() {

                    @Override
                    public T run() throws Exception {
                        return action.call();
                    }
                });
            } catch (PrivilegedActionException e) {
                throw new PrivilegeException(e.getCause());
            }
        }
    }
}
