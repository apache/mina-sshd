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

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.spi.FileSystemProvider;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.sshd.common.util.GenericUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseFileSystem<T extends Path> extends FileSystem {
    protected final Logger log;
    private final FileSystemProvider fileSystemProvider;

    public BaseFileSystem(FileSystemProvider fileSystemProvider) {
        this.log = LoggerFactory.getLogger(getClass());
        this.fileSystemProvider = Objects.requireNonNull(fileSystemProvider, "No file system provider");
    }

    public T getDefaultDir() {
        return getPath("/");
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public FileSystemProvider provider() {
        return fileSystemProvider;
    }

    @Override
    public String getSeparator() {
        return "/";
    }

    @Override
    public Iterable<Path> getRootDirectories() {
        return Collections.singleton(create("/"));
    }

    @Override
    public Iterable<FileStore> getFileStores() {
        throw new UnsupportedOperationException("No file stores available");
    }

    @Override
    public T getPath(String first, String... more) {
        StringBuilder sb = new StringBuilder();
        if (!GenericUtils.isEmpty(first)) {
            appendDedupSep(sb, first.replace('\\', '/')); // in case we are running on Windows
        }

        if (GenericUtils.length(more) > 0) {
            for (String segment : more) {
                if ((sb.length() > 0) && (sb.charAt(sb.length() - 1) != '/')) {
                    sb.append('/');
                }
                // in case we are running on Windows
                appendDedupSep(sb, segment.replace('\\', '/'));
            }
        }

        if ((sb.length() > 1) && (sb.charAt(sb.length() - 1) == '/')) {
            sb.setLength(sb.length() - 1);
        }

        String path = sb.toString();
        String root = null;
        if (path.startsWith("/")) {
            root = "/";
            path = path.substring(1);
        }

        String[] names = GenericUtils.split(path, '/');
        T p = create(root, names);
        if (log.isTraceEnabled()) {
            log.trace("getPath({}, {}): {}", first, Arrays.toString(more), p);
        }

        return p;
    }

    protected void appendDedupSep(StringBuilder sb, CharSequence s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if ((ch != '/') || (sb.length() == 0) || (sb.charAt(sb.length() - 1) != '/')) {
                sb.append(ch);
            }
        }
    }

    @Override
    public PathMatcher getPathMatcher(String syntaxAndPattern) {
        int colonIndex = Objects.requireNonNull(syntaxAndPattern, "No argument").indexOf(':');
        if ((colonIndex <= 0) || (colonIndex == syntaxAndPattern.length() - 1)) {
            throw new IllegalArgumentException(
                    "syntaxAndPattern must have form \"syntax:pattern\" but was \"" + syntaxAndPattern + "\"");
        }

        String syntax = syntaxAndPattern.substring(0, colonIndex);
        String pattern = syntaxAndPattern.substring(colonIndex + 1);
        String expr;
        switch (syntax) {
            case "glob":
                expr = globToRegex(pattern);
                break;
            case "regex":
                expr = pattern;
                break;
            default:
                throw new UnsupportedOperationException("Unsupported path matcher syntax: \'" + syntax + "\'");
        }
        if (log.isTraceEnabled()) {
            log.trace("getPathMatcher({}): {}", syntaxAndPattern, expr);
        }

        Pattern regex = Pattern.compile(expr);
        return path -> {
            Matcher m = regex.matcher(path.toString());
            return m.matches();
        };
    }

    protected String globToRegex(String pattern) {
        StringBuilder sb = new StringBuilder(Objects.requireNonNull(pattern, "No pattern").length());
        int inGroup = 0;
        int inClass = 0;
        int firstIndexInClass = -1;
        char[] arr = pattern.toCharArray();
        for (int i = 0; i < arr.length; i++) {
            char ch = arr[i];
            switch (ch) {
                case '\\':
                    i++;
                    if (i >= arr.length) {
                        sb.append('\\');
                    } else {
                        char next = arr[i];
                        switch (next) {
                            case ',':
                                // escape not needed
                                break;
                            case 'Q':
                            case 'E':
                                // extra escape needed
                                sb.append("\\\\");
                                break;
                            default:
                                sb.append('\\');
                                break;
                        }
                        sb.append(next);
                    }
                    break;
                case '*':
                    sb.append((inClass == 0) ? ".*" : "*");
                    break;
                case '?':
                    sb.append((inClass == 0) ? '.' : '?');
                    break;
                case '[':
                    inClass++;
                    firstIndexInClass = i + 1;
                    sb.append('[');
                    break;
                case ']':
                    inClass--;
                    sb.append(']');
                    break;
                case '.':
                case '(':
                case ')':
                case '+':
                case '|':
                case '^':
                case '$':
                case '@':
                case '%':
                    if ((inClass == 0) || ((firstIndexInClass == i) && (ch == '^'))) {
                        sb.append('\\');
                    }
                    sb.append(ch);
                    break;
                case '!':
                    sb.append((firstIndexInClass == i) ? '^' : '!');
                    break;
                case '{':
                    inGroup++;
                    sb.append('(');
                    break;
                case '}':
                    inGroup--;
                    sb.append(')');
                    break;
                case ',':
                    sb.append((inGroup > 0) ? '|' : ',');
                    break;
                default:
                    sb.append(ch);
            }
        }

        String regex = sb.toString();
        if (log.isTraceEnabled()) {
            log.trace("globToRegex({}): {}", pattern, regex);
        }

        return regex;
    }

    @Override
    public WatchService newWatchService() throws IOException {
        throw new UnsupportedOperationException("Watch service N/A");
    }

    protected T create(String root, String... names) {
        return create(root, GenericUtils.unmodifiableList(names));
    }

    protected T create(String root, Collection<String> names) {
        return create(root, GenericUtils.unmodifiableList(names));
    }

    protected abstract T create(String root, List<String> names);
}
