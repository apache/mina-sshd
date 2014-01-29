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
package org.apache.sshd.common;

import java.io.IOException;
import java.util.List;

public interface ServiceFactory {

    /**
     * Name of this factory
     * @return
     */
    String getName();

    Service create(Session session) throws IOException;

    /**
     * Utility class to help using NamedFactories
     */
    public static class Utils {

        /**
         * Create an instance of the specified name by looking up the needed factory
         * in the list.
         *
         * @param factories list of available factories
         * @param name the factory name to use
         * @return a newly created object or <code>null</code> if the factory is not in the list
         */
        public static Service create(List<ServiceFactory> factories, String name, Session session) throws IOException {
            if (factories != null) {
                for (ServiceFactory f : factories) {
                    if (f.getName().equals(name)) {
                        return f.create(session);
                    }
                }
            }
            return null;
        }
    }
}
