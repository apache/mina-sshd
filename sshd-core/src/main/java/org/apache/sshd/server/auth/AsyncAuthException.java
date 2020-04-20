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

package org.apache.sshd.server.auth;

import java.lang.reflect.Array;
import java.util.function.Consumer;

import org.apache.sshd.common.RuntimeSshException;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class AsyncAuthException extends RuntimeSshException {

    private static final long serialVersionUID = 6741236101797649869L;

    protected Object listener;
    protected Boolean authed;

    public AsyncAuthException() {
        super();
    }

    public void setAuthed(boolean authed) {
        Object listener;
        synchronized (this) {
            if (this.authed != null) {
                return;
            }
            this.authed = authed;
            listener = this.listener;
        }

        if (listener != null) {
            if (listener instanceof Consumer<?>) {
                Consumer<? super Boolean> lst = asListener(listener);
                lst.accept(authed);
            } else {
                int l = Array.getLength(listener);
                for (int i = 0; i < l; i++) {
                    Object lstInstance = Array.get(listener, i);
                    Consumer<? super Boolean> lst = asListener(lstInstance);
                    if (lst != null) {
                        lst.accept(authed);
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    protected Consumer<? super Boolean> asListener(Object listener) {
        return (Consumer<? super Boolean>) listener;
    }

    public void addListener(Consumer<? super Boolean> listener) {
        Boolean result;
        synchronized (this) {
            if (this.listener == null) {
                this.listener = listener;
            } else if (this.listener instanceof Consumer<?>) {
                this.listener = new Object[] { this.listener, listener };
            } else {
                Object[] ol = (Object[]) this.listener;
                int l = ol.length;
                Object[] nl = new Object[l + 1];
                System.arraycopy(ol, 0, nl, 0, l);
                nl[l] = listener;
                this.listener = nl;
            }
            result = this.authed;
        }
        if (result != null) {
            listener.accept(result);
        }
    }
}
