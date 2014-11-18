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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * A named factory is a factory identified by a name.
 * Such names are used mainly in the algorithm negotiation at the beginning of the SSH connection.
 *
 * @param <T>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface NamedFactory<T> extends Factory<T> {

    /**
     * Name of this factory
     * @return the name of this factory
     */
    String getName();

    /**
     * Utility class to help using NamedFactories
     */
    public static class Utils {
    	/**
    	 * @param factories The named factories
    	 * @return A {@link List} of all the factories names - in same order
    	 * as they appear in the input collection
    	 */
    	public static <T> List<String> getNameList(Collection<NamedFactory<T>> factories) {
    		if ((factories == null) || factories.isEmpty()) {
    			return Collections.emptyList();
    		}
    		
    		List<String>	names=new ArrayList<String>(factories.size());
    		for (NamedFactory<T> f : factories) {
    			names.add(f.getName());
    		}
    		
    		return names;
    	}
        /**
         * Create an instance of the specified name by looking up the needed factory
         * in the list.
         * 
         * @param factories list of available factories
         * @param name the factory name to use
         * @param <T> type of object to create
         * @return a newly created object or <code>null</code> if the factory is not in the list
         */
        public static <T> T create(List<NamedFactory<T>> factories, String name) {
            if (factories != null) {
                for (NamedFactory<T> f : factories) {
                    if (f.getName().equals(name)) {
                        return f.create();
                    }
                }
            }
            return null;
        }

        /**
         * Get a comma separated list of the factory names from the given list.
         *
         * @param factories list of available factories
         * @param <T> type of object to create
         * @return a comma separated list of factory names
         */
        public static <T> String getNames(List<NamedFactory<T>> factories) {
            StringBuilder sb = new StringBuilder();
            for (NamedFactory<T> f : factories) {
                if (sb.length() > 0) {
                    sb.append(",");
                }
                sb.append(f.getName());
            }
            return sb.toString();
        }

        /**
         * Remove the factory identified by the name from the list.
         *
         * @param factories list of factories
         * @param name the name of the factory to remove
         * @param <T> type of object to create
         * @return the factory removed from the list or <code>null</code> if not in the list
         */
        public static <T> NamedFactory<T> remove(List<NamedFactory<T>> factories, String name) {
            for (NamedFactory<T> f : factories) {
                if (f.getName().equals(name)) {
                    factories.remove(f);
                    return f;
                }
            }
            return null;
        }

        /**
         * Retrieve the factory identified by its name from the list.
         *
         * @param factories list of available factories
         * @param name the name of the factory to retrieve
         * @param <T> type of object create by the factories
         * @return a factory or <code>null</code> if not found in the list
         */
        public static <T> NamedFactory<T> get(List<NamedFactory<T>> factories, String name) {
            for (NamedFactory<T> f : factories) {
                if (f.getName().equals(name)) {
                    return f;
                }
            }
            return null;
        }

    }

}
