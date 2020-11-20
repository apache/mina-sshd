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

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
@FunctionalInterface
public interface NamedResource {

    /**
     * Returns the value of {@link #getName()} - or {@code null} if argument is {@code null}
     */
    Function<NamedResource, String> NAME_EXTRACTOR = input -> input == null ? null : input.getName();

    /**
     * Compares 2 {@link NamedResource}s according to their {@link #getName()} value case <U>insensitive</U>
     */
    Comparator<NamedResource> BY_NAME_COMPARATOR = Comparator.comparing(NAME_EXTRACTOR, String.CASE_INSENSITIVE_ORDER);

    /**
     * @return The resource name
     */
    String getName();

    /**
     * @param  resources The named resources
     * @return           A {@link List} of all the factories names - in same order as they appear in the input
     *                   collection
     */
    static List<String> getNameList(Collection<? extends NamedResource> resources) {
        return GenericUtils.map(resources, NamedResource::getName);
    }

    /**
     * @param  resources list of available resources
     * @return           A comma separated list of factory names
     */
    static String getNames(Collection<? extends NamedResource> resources) {
        Collection<String> nameList = getNameList(resources);
        return GenericUtils.join(nameList, ',');
    }

    /**
     * Remove the resource identified by the name from the list.
     *
     * @param  <R>       The generic resource type
     * @param  name      Name of the resource - ignored if {@code null}/empty
     * @param  c         The {@link Comparator} to decide whether the {@link NamedResource#getName()} matches the
     *                   <tt>name</tt> parameter
     * @param  resources The {@link NamedResource} to check - ignored if {@code null}/empty
     * @return           the removed resource from the list or {@code null} if not in the list
     */
    static <R extends NamedResource> R removeByName(
            String name, Comparator<? super String> c, Collection<? extends R> resources) {
        R r = findByName(name, c, resources);
        if (r != null) {
            resources.remove(r);
        }
        return r;
    }

    /**
     * @param  <R>       The generic resource type
     * @param  name      Name of the resource - ignored if {@code null}/empty
     * @param  c         The {@link Comparator} to decide whether the {@link NamedResource#getName()} matches the
     *                   <tt>name</tt> parameter
     * @param  resources The {@link NamedResource} to check - ignored if {@code null}/empty
     * @return           The <U>first</U> resource whose name matches the parameter (by invoking
     *                   {@link Comparator#compare(Object, Object)} - {@code null} if no match found
     */
    static <R extends NamedResource> R findByName(
            String name, Comparator<? super String> c, Collection<? extends R> resources) {
        return (GenericUtils.isEmpty(name) || GenericUtils.isEmpty(resources))
                ? null
                : GenericUtils.stream(resources)
                        .filter(r -> c.compare(name, r.getName()) == 0)
                        .findFirst()
                        .orElse(null);
    }

    static <R extends NamedResource> R findFirstMatchByName(
            Collection<String> names, Comparator<? super String> c, Collection<? extends R> resources) {
        return (GenericUtils.isEmpty(names) || GenericUtils.isEmpty(resources))
                ? null
                : GenericUtils.stream(resources)
                        .filter(r -> GenericUtils.findFirstMatchingMember(n -> c.compare(n, r.getName()) == 0, names) != null)
                        .findFirst()
                        .orElse(null);

    }

    /**
     * Wraps a name value inside a {@link NamedResource}
     *
     * @param  name The name value to wrap
     * @return      The wrapper instance
     */
    static NamedResource ofName(String name) {
        return new NamedResource() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public String toString() {
                return getName();
            }
        };
    }

    static int safeCompareByName(NamedResource r1, NamedResource r2, boolean caseSensitive) {
        String n1 = (r1 == null) ? null : r1.getName();
        String n2 = (r2 == null) ? null : r2.getName();
        return GenericUtils.safeCompare(n1, n2, caseSensitive);
    }
}
