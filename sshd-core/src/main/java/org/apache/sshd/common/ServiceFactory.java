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
package org.apache.sshd.common;

import java.io.IOException;
import java.util.Collection;

import org.apache.sshd.common.session.Session;

public interface ServiceFactory extends NamedResource {
    Service create(Session session) throws IOException;

    /**
     * Create an instance of the specified name by looking up the needed factory in the list (case <U>insensitive</U>.
     *
     * @param  factories   list of available factories
     * @param  name        the factory name to use
     * @param  session     the referenced {@link Session}
     * @return             a newly created object or {@code null} if the factory is not in the list
     * @throws IOException if session creation failed
     * @see                ServiceFactory#create(Session)
     */
    static Service create(Collection<? extends ServiceFactory> factories, String name, Session session) throws IOException {
        ServiceFactory factory = NamedResource.findByName(name, String.CASE_INSENSITIVE_ORDER, factories);
        if (factory == null) {
            return null;
        } else {
            return factory.create(session);
        }
    }
}
