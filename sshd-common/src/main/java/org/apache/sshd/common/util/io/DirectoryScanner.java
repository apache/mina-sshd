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
package org.apache.sshd.common.util.io;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Objects;
import java.util.function.Supplier;

import org.apache.sshd.common.util.GenericUtils;

/**
 * <p>
 * Class for scanning a directory for files/directories which match certain criteria.
 * </p>
 *
 * <p>
 * These criteria consist of selectors and patterns which have been specified. With the selectors you can select which
 * files you want to have included. Files which are not selected are excluded. With patterns you can include or exclude
 * files based on their filename.
 * </p>
 *
 * <p>
 * The idea is simple. A given directory is recursively scanned for all files and directories. Each file/directory is
 * matched against a set of selectors, including special support for matching against filenames with include and and
 * exclude patterns. Only files/directories which match at least one pattern of the include pattern list or other file
 * selector, and don't match any pattern of the exclude pattern list or fail to match against a required selector will
 * be placed in the list of files/directories found.
 * </p>
 *
 * <p>
 * When no list of include patterns is supplied, "**" will be used, which means that everything will be matched. When no
 * list of exclude patterns is supplied, an empty list is used, such that nothing will be excluded. When no selectors
 * are supplied, none are applied.
 * </p>
 *
 * <p>
 * The filename pattern matching is done as follows: The name to be matched is split up in path segments. A path segment
 * is the name of a directory or file, which is bounded by <code>File.separator</code> ('/' under UNIX, '\' under
 * Windows). For example, "abc/def/ghi/xyz.java" is split up in the segments "abc", "def","ghi" and "xyz.java". The same
 * is done for the pattern against which should be matched.
 * </p>
 *
 * <p>
 * The segments of the name and the pattern are then matched against each other. When '**' is used for a path segment in
 * the pattern, it matches zero or more path segments of the name.
 * </p>
 *
 * <p>
 * There is a special case regarding the use of <code>File.separator</code>s at the beginning of the pattern and the
 * string to match:<br>
 * When a pattern starts with a <code>File.separator</code>, the string to match must also start with a
 * <code>File.separator</code>. When a pattern does not start with a <code>File.separator</code>, the string to match
 * may not start with a <code>File.separator</code>. When one of these rules is not obeyed, the string will not match.
 * </p>
 *
 * <p>
 * When a name path segment is matched against a pattern path segment, the following special characters can be used:<br>
 * '*' matches zero or more characters<br>
 * '?' matches one character.
 * </p>
 *
 * <p>
 * Examples: <br>
 * <code>"**\*.class"</code> matches all <code>.class</code> files/dirs in a directory tree. <br>
 * <code>"test\a??.java"</code> matches all files/dirs which start with an 'a', then two more characters and then
 * <code>".java"</code>, in a directory called test. <br>
 * <code>"**"</code> matches everything in a directory tree. <br>
 * <code>"**\test\**\XYZ*"</code> matches all files/dirs which start with <code>"XYZ"</code> and where there is a parent
 * directory called test (e.g. <code>"abc\test\def\ghi\XYZ123"</code>).
 * </p>
 *
 * <p>
 * Case sensitivity may be turned off if necessary. By default, it is turned on.
 * </p>
 *
 * <p>
 * Example of usage:
 * </p>
 *
 * <pre>
 * String[] includes = { "**\\*.class" };
 * String[] excludes = { "modules\\*\\**" };
 * ds.setIncludes(includes);
 * ds.setExcludes(excludes);
 * ds.setBasedir(new File("test"));
 * ds.setCaseSensitive(true);
 * ds.scan();
 *
 * System.out.println("FILES:");
 * String[] files = ds.getIncludedFiles();
 * for (int i = 0; i &lt; files.length; i++) {
 *     System.out.println(files[i]);
 * }
 * </pre>
 * <p>
 * This will scan a directory called test for .class files, but excludes all files in all proper subdirectories of a
 * directory called "modules".
 * </p>
 *
 * @author Arnout J. Kuiper <a href="mailto:ajkuiper@wxs.nl">ajkuiper@wxs.nl</a>
 * @author Magesh Umasankar
 * @author <a href="mailto:bruce@callenish.com">Bruce Atherton</a>
 * @author <a href="mailto:levylambert@tiscali-dsl.de">Antoine Levy-Lambert</a>
 */
public class DirectoryScanner extends PathScanningMatcher {
    /**
     * The base directory to be scanned.
     */
    protected Path basedir;

    public DirectoryScanner() {
        super();
    }

    public DirectoryScanner(Path dir) {
        this(dir, Collections.emptyList());
    }

    public DirectoryScanner(Path dir, String... includes) {
        this(dir, GenericUtils.isEmpty(includes) ? Collections.emptyList() : Arrays.asList(includes));
    }

    public DirectoryScanner(Path dir, Collection<String> includes) {
        setBasedir(dir);
        setIncludes(includes);
    }

    /**
     * Sets the base directory to be scanned. This is the directory which is scanned recursively.
     *
     * @param basedir The base directory for scanning. Should not be {@code null}.
     */
    public void setBasedir(Path basedir) {
        this.basedir = Objects.requireNonNull(basedir, "No base directory provided");
    }

    /**
     * Returns the base directory to be scanned. This is the directory which is scanned recursively.
     *
     * @return the base directory to be scanned
     */
    public Path getBasedir() {
        return basedir;
    }

    /**
     * Scans the base directory for files which match at least one include pattern and don't match any exclude patterns.
     * If there are selectors then the files must pass muster there, as well.
     *
     * @return                       the matching files
     * @throws IllegalStateException if the base directory was set incorrectly (i.e. if it is {@code null}, doesn't
     *                               exist, or isn't a directory).
     * @throws IOException           if failed to scan the directory (e.g., access denied)
     */
    public Collection<Path> scan() throws IOException, IllegalStateException {
        return scan(LinkedList::new);
    }

    public <C extends Collection<Path>> C scan(Supplier<? extends C> factory) throws IOException, IllegalStateException {
        Path dir = getBasedir();
        if (dir == null) {
            throw new IllegalStateException("No basedir set");
        }
        if (!Files.exists(dir)) {
            throw new IllegalStateException("basedir " + dir + " does not exist");
        }
        if (!Files.isDirectory(dir)) {
            throw new IllegalStateException("basedir " + dir + " is not a directory");
        }
        if (GenericUtils.isEmpty(getIncludes())) {
            throw new IllegalStateException("No includes set for " + dir);
        }

        FileSystem fs = dir.getFileSystem();
        String fsSep = fs.getSeparator();
        String curSep = getSeparator();
        if (!Objects.equals(fsSep, curSep)) {
            throw new IllegalStateException("Mismatched separator - expected=" + curSep + ", actual=" + fsSep);
        }

        return scandir(dir, dir, factory.get());
    }

    /**
     * Scans the given directory for files and directories. Found files and directories are placed in their respective
     * collections, based on the matching of includes, excludes, and the selectors. When a directory is found, it is
     * scanned recursively.
     *
     * @param  <C>         Target matches collection type
     * @param  rootDir     The directory to scan. Must not be {@code null}.
     * @param  dir         The path relative to the root directory (needed to prevent problems with an absolute path
     *                     when using <tt>dir</tt>). Must not be {@code null}.
     * @param  filesList   Target {@link Collection} to accumulate the relative path matches
     * @return             Updated files list
     * @throws IOException if failed to scan the directory
     */
    protected <C extends Collection<Path>> C scandir(Path rootDir, Path dir, C filesList) throws IOException {
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            for (Path p : ds) {
                Path rel = rootDir.relativize(p);
                String name = rel.toString();
                if (Files.isDirectory(p)) {
                    if (isIncluded(name)) {
                        filesList.add(p);
                        scandir(rootDir, p, filesList);
                    } else if (couldHoldIncluded(name)) {
                        scandir(rootDir, p, filesList);
                    }
                } else if (Files.isRegularFile(p)) {
                    if (isIncluded(name)) {
                        filesList.add(p);
                    }
                }
            }
        }

        return filesList;
    }
}
