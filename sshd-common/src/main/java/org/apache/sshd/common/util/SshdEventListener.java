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

import java.lang.reflect.Proxy;
import java.util.EventListener;
import java.util.Objects;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface SshdEventListener extends EventListener {

    /**
     * Makes sure that the listener is neither {@code null} nor a proxy
     *
     * @param  <L>      Type of {@link SshdEventListener} being validation
     * @param  listener The listener instance
     * @param  prefix   Prefix text to be prepended to validation failure messages
     * @return          The validated instance
     */
    static <L extends SshdEventListener> L validateListener(L listener, String prefix) {
        Objects.requireNonNull(listener, prefix + ": no instance");
        ValidateUtils.checkTrue(!Proxy.isProxyClass(listener.getClass()), prefix + ": proxies N/A");
        return listener;
    }
}
