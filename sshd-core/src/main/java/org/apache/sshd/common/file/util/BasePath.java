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
package org.apache.sshd.common.file.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.ProviderMismatchException;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.AbstractList;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

public abstract class BasePath<T extends BasePath<T, FS>, FS extends BaseFileSystem<T>> implements Path {

    protected final FS fileSystem;
    protected final String root;
    protected final ImmutableList<String> names;

    public BasePath(FS fileSystem, String root, ImmutableList<String> names) {
        this.fileSystem = fileSystem;
        this.root = root;
        this.names = names;
    }

    @SuppressWarnings("unchecked")
    protected T asT() {
        return (T) this;
    }
    protected T create(String root, String... names) {
        return create(root, new ImmutableList<>(names));
    }

    protected T create(String root, Collection<String> names) {
        return create(root, new ImmutableList<>(names.toArray(new String[names.size()])));
    }

    protected T create(String root, ImmutableList<String> names) {
        return fileSystem.create(root, names);
    }

    public FS getFileSystem() {
        return fileSystem;
    }

    public boolean isAbsolute() {
        return root != null;
    }

    public T getRoot() {
        if (isAbsolute()) {
            return create(root);
        }
        return null;
    }

    public T getFileName() {
        if (!names.isEmpty()) {
            return create(null, names.get(names.size() - 1));
        }
        return null;
    }

    public T getParent() {
        if (names.isEmpty() || names.size() == 1 && root == null) {
            return null;
        }
        return create(root, names.subList(0, names.size() - 1));
    }

    public int getNameCount() {
        return names.size();
    }

    public T getName(int index) {
        if (index < 0 || index >= names.size()) {
            throw new IllegalArgumentException();
        }
        return create(null, names.subList(index, index + 1));
    }

    public T subpath(int beginIndex, int endIndex) {
        if ((beginIndex < 0) || (beginIndex >= names.size()) || (endIndex > names.size()) || (beginIndex >= endIndex)) {
            throw new IllegalArgumentException();
        }
        return create(null, names.subList(beginIndex, endIndex));
    }

    private static boolean startsWith(List<?> list, List<?> other) {
        return list.size() >= other.size() && list.subList(0, other.size()).equals(other);
    }

    public boolean startsWith(Path other) {
        T p1 = asT();
        T p2 = checkPath(other);
        return p1.getFileSystem().equals(p2.getFileSystem())
                && Objects.equals(p1.root, p2.root)
                && startsWith(p1.names, p2.names);
    }

    public boolean startsWith(String other) {
        return startsWith(getFileSystem().getPath(other));
    }

    private static boolean endsWith(List<?> list, List<?> other) {
        return other.size() <= list.size() && list.subList(list.size() - other.size(), list.size()).equals(other);
    }

    public boolean endsWith(Path other) {
        T p1 = asT();
        T p2 = checkPath(other);
        if (p2.isAbsolute()) {
            return p1.compareTo(p2) == 0;
        }
        return endsWith(p1.names, p2.names);
    }

    public boolean endsWith(String other) {
        return endsWith(getFileSystem().getPath(other));
    }

    private boolean isNormal() {
        if (getNameCount() == 0 || getNameCount() == 1 && !isAbsolute()) {
            return true;
        }
        boolean foundNonParentName = isAbsolute(); // if there's a root, the path doesn't start with ..
        boolean normal = true;
        for (String name : names) {
            if (name.equals("..")) {
                if (foundNonParentName) {
                    normal = false;
                    break;
                }
            } else {
                if (name.equals(".")) {
                    normal = false;
                    break;
                }
                foundNonParentName = true;
            }
        }
        return normal;
    }

    public T normalize() {
        if (isNormal()) {
            return asT();
        }

        Deque<String> newNames = new ArrayDeque<>();
        for (String name : names) {
            if (name.equals("..")) {
                String lastName = newNames.peekLast();
                if (lastName != null && !lastName.equals("..")) {
                    newNames.removeLast();
                } else if (!isAbsolute()) {
                    // if there's a root and we have an extra ".." that would go up above the root, ignore it
                    newNames.add(name);
                }
            } else if (!name.equals(".")) {
                newNames.add(name);
            }
        }

        return newNames.equals(names) ? asT() : create(root, newNames);
    }

    public T resolve(Path other) {
        T p1 = asT();
        T p2 = checkPath(other);
        if (p2.isAbsolute()) {
            return p2;
        }
        if (p2.names.isEmpty()) {
            return p1;
        }
        String[] names = new String[p1.names.size() + p2.names.size()];
        int index = 0;
        for (String p : p1.names) {
            names[index++] = p;
        }
        for (String p : p2.names) {
            names[index++] = p;
        }
        return create(p1.root, names);
    }

    public T resolve(String other) {
        return resolve(getFileSystem().getPath(other));
    }

    public Path resolveSibling(Path other) {
        if (other == null) {
            throw new NullPointerException();
        }
        T parent = getParent();
        return parent == null ? other : parent.resolve(other);
    }

    public Path resolveSibling(String other) {
        return resolveSibling(getFileSystem().getPath(other));
    }

    public T relativize(Path other) {
        T p1 = asT();
        T p2 = checkPath(other);
        if (!Objects.equals(p1.getRoot(), p2.getRoot())) {
            throw new IllegalArgumentException("Paths have different roots: " + this + ", " + other);
        }
        if (p2.equals(p1)) {
            return create(null);
        }
        if (p1.root == null && p1.names.isEmpty()) {
            return p2;
        }
        // Common subsequence
        int sharedSubsequenceLength = 0;
        for (int i = 0; i < Math.min(p1.names.size(), p2.names.size()); i++) {
            if (p1.names.get(i).equals(p2.names.get(i))) {
                sharedSubsequenceLength++;
            } else {
                break;
            }
        }
        int extraNamesInThis = Math.max(0, p1.names.size() - sharedSubsequenceLength);
        List<String> extraNamesInOther = (p2.names.size() <= sharedSubsequenceLength)
                ? Collections.<String>emptyList()
                : p2.names.subList(sharedSubsequenceLength, p2.names.size());
        List<String> parts = new ArrayList<>(extraNamesInThis + extraNamesInOther.size());
        // add .. for each extra name in this path
        parts.addAll(Collections.nCopies(extraNamesInThis, ".."));
        // add each extra name in the other path
        parts.addAll(extraNamesInOther);
        return create(null, parts);
    }

    public T toAbsolutePath() {
        if (isAbsolute()) {
            return asT();
        }
        return fileSystem.getDefaultDir().resolve(this);
    }

    public File toFile() {
        throw new UnsupportedOperationException();
    }

    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>[] events, WatchEvent.Modifier... modifiers) throws IOException {
        throw new UnsupportedOperationException();
    }

    public WatchKey register(WatchService watcher, WatchEvent.Kind<?>... events) throws IOException {
        throw new UnsupportedOperationException();
    }

    public Iterator<Path> iterator() {
        return new AbstractList<Path>() {
            @Override
            public Path get(int index) {
                return getName(index);
            }

            @Override
            public int size() {
                return getNameCount();
            }
        }.iterator();
    }

    public int compareTo(Path paramPath) {
        T p1 = asT();
        T p2 = checkPath(paramPath);
        int c = compare(p1.root, p2.root);
        if (c != 0) {
            return c;
        }
        for (int i = 0; i < Math.min(p1.names.size(), p2.names.size()); i++) {
            String n1 = p1.names.get(i);
            String n2 = p2.names.get(i);
            c = compare(n1, n2);
            if (c != 0) {
                return c;
            }
        }
        return p1.names.size() - p2.names.size();
    }

    private int compare(String s1, String s2) {
        if (s1 == null) {
            return s2 == null ? 0 : -1;
        } else {
            return s2 == null ? +1 : s1.compareTo(s2);
        }
    }

    @SuppressWarnings("unchecked")
    private T checkPath(Path paramPath) {
        if (paramPath == null) {
            throw new NullPointerException();
        }
        if (paramPath.getClass() != getClass()) {
            throw new ProviderMismatchException();
        }
        T t = (T) paramPath;
        if (t.fileSystem.provider() != this.fileSystem.provider()) {
            throw new ProviderMismatchException();
        }
        return t;
    }

    @Override
    public int hashCode() {
        int hash = getFileSystem().hashCode();
        // use hash codes from toString() form of names
        hash = 31 * hash + (root == null ? 0 : root.hashCode());
        for (String name : names) {
            hash = 31 * hash + name.hashCode();
        }
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof Path
                && compareTo((Path) obj) == 0;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (root != null) {
            sb.append(root);
        }
        for (String name : names) {
            if (sb.length() > 0 && sb.charAt(sb.length()  - 1) != '/') {
                sb.append(fileSystem.getSeparator());
            }
            sb.append(name);
        }
        return sb.toString();
    }

}
