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
package org.apache.sshd.common.file.util;

import java.util.AbstractList;

/**
 * Simple immutable array list
 *
 * @param <T> The element type
 */
public class ImmutableList<T> extends AbstractList<T> {

    private final T[] data;
    private final int from;
    private final int to;

    public ImmutableList(T[] data) {
        this(data, 0, data.length);
    }

    public ImmutableList(T[] data, int from, int to) {
        this.data = data;
        this.from = from;
        this.to = to;
    }

    @Override
    public T get(int index) {
        return data[from + index];
    }

    @Override
    public int size() {
        return to - from;
    }

    @Override
    public ImmutableList<T> subList(int fromIndex, int toIndex) {
        if (fromIndex == from && toIndex == to) {
            return this;
        }
        return new ImmutableList<>(data, from + fromIndex, from + toIndex);
    }

}
