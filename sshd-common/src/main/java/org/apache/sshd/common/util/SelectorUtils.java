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

import java.io.File;
import java.nio.file.FileSystem;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.StringTokenizer;

/**
 * <p>
 * This is a utility class used by selectors and DirectoryScanner. The functionality more properly belongs just to
 * selectors, but unfortunately DirectoryScanner exposed these as protected methods. Thus we have to support any
 * subclasses of DirectoryScanner that may access these methods.
 * </p>
 * <p>
 * This is a Singleton.
 * </p>
 *
 * @author  Arnout J. Kuiper <a href="mailto:ajkuiper@wxs.nl">ajkuiper@wxs.nl</a>
 * @author  Magesh Umasankar
 * @author  <a href="mailto:bruce@callenish.com">Bruce Atherton</a>
 * @version $Id$
 * @since   1.5
 */
public final class SelectorUtils {

    public static final String PATTERN_HANDLER_PREFIX = "[";

    public static final String PATTERN_HANDLER_SUFFIX = "]";

    public static final String REGEX_HANDLER_PREFIX = "%regex" + PATTERN_HANDLER_PREFIX;

    public static final String ANT_HANDLER_PREFIX = "%ant" + PATTERN_HANDLER_PREFIX;

    /**
     * Private Constructor
     */
    private SelectorUtils() {
        throw new UnsupportedOperationException("No instance allowed");
    }

    /**
     * <p>
     * Tests whether or not a given path matches the start of a given pattern up to the first "**".
     * </p>
     *
     * <p>
     * This is not a general purpose test and should only be used if you can live with false positives. For example,
     * <code>pattern=**\a</code> and <code>str=b</code> will yield <code>true</code>.
     * </p>
     *
     * @param  pattern The pattern to match against. Must not be {@code null}.
     * @param  str     The path to match, as a String. Must not be {@code null}.
     * @return         whether or not a given path matches the start of a given pattern up to the first "**".
     */
    public static boolean matchPatternStart(String pattern, String str) {
        return matchPatternStart(pattern, str, true);
    }

    /**
     * <p>
     * Tests whether or not a given path matches the start of a given pattern up to the first "**".
     * </p>
     *
     * <p>
     * This is not a general purpose test and should only be used if you can live with false positives. For example,
     * <code>pattern=**\a</code> and <code>str=b</code> will yield <code>true</code>.
     * </p>
     *
     * @param  pattern         The pattern to match against. Must not be {@code null}.
     * @param  str             The path to match, as a String. Must not be {@code null}.
     * @param  isCaseSensitive Whether or not matching should be performed case sensitively.
     * @return                 whether or not a given path matches the start of a given pattern up to the first
     *                         &quot;**&quot;.
     */
    public static boolean matchPatternStart(String pattern, String str, boolean isCaseSensitive) {
        return matchPath(pattern, str, File.separator, isCaseSensitive);
    }

    public static boolean matchPatternStart(
            String pattern, String str, String separator, boolean isCaseSensitive) {
        if ((pattern.length() > (REGEX_HANDLER_PREFIX.length() + PATTERN_HANDLER_SUFFIX.length() + 1))
                && pattern.startsWith(REGEX_HANDLER_PREFIX)
                && pattern.endsWith(PATTERN_HANDLER_SUFFIX)) {
            // FIXME: ICK! But we can't do partial matches for regex, so we have to reserve judgement until we have
            // a file to deal with, or we can definitely say this is an exclusion...
            return true;
        } else {
            if ((pattern.length() > (ANT_HANDLER_PREFIX.length() + PATTERN_HANDLER_SUFFIX.length() + 1))
                    && pattern.startsWith(ANT_HANDLER_PREFIX)
                    && pattern.endsWith(PATTERN_HANDLER_SUFFIX)) {
                pattern = pattern.substring(ANT_HANDLER_PREFIX.length(), pattern.length() - PATTERN_HANDLER_SUFFIX.length());
            }

            if (matchAntPathPatternStart(pattern, str, separator, isCaseSensitive)) {
                return true;
            }

            return matchAntPathPatternStart(pattern, str.replace('\\', '/'), "/", isCaseSensitive);
        }
    }

    public static boolean matchAntPathPatternStart(
            String pattern, String str, String separator, boolean isCaseSensitive) {
        // When str starts with a File.separator, pattern has to start with a
        // File.separator.
        // When pattern starts with a File.separator, str has to start with a
        // File.separator.
        if (str.startsWith(separator) != pattern.startsWith(separator)) {
            return false;
        }

        List<String> patDirs = tokenizePath(pattern, separator);
        List<String> strDirs = tokenizePath(str, separator);

        int patIdxStart = 0;
        int patIdxEnd = patDirs.size() - 1;
        int strIdxStart = 0;
        int strIdxEnd = strDirs.size() - 1;

        // up to first '**'
        while (patIdxStart <= patIdxEnd && strIdxStart <= strIdxEnd) {
            String patDir = patDirs.get(patIdxStart);
            if (patDir.equals("**")) {
                break;
            }
            if (!match(patDir, strDirs.get(strIdxStart), isCaseSensitive)) {
                return false;
            }
            patIdxStart++;
            strIdxStart++;
        }

        // CHECKSTYLE:OFF
        if (strIdxStart > strIdxEnd) {
            // String is exhausted
            return true;
        } else {
            return patIdxStart <= patIdxEnd;
        }
        // CHECKSTYLE:ON
    }

    /**
     * Tests whether or not a given path matches a given pattern.
     *
     * @param  pattern The pattern to match against. Must not be {@code null}.
     * @param  str     The path to match, as a String. Must not be {@code null}.
     * @return         <code>true</code> if the pattern matches against the string, or <code>false</code> otherwise.
     */
    public static boolean matchPath(String pattern, String str) {
        return matchPath(pattern, str, true);
    }

    /**
     * Tests whether or not a given path matches a given pattern.
     *
     * @param  pattern         The pattern to match against. Must not be {@code null}.
     * @param  str             The path to match, as a String. Must not be {@code null}.
     * @param  isCaseSensitive Whether or not matching should be performed case sensitively.
     * @return                 <code>true</code> if the pattern matches against the string, or <code>false</code>
     *                         otherwise.
     */
    public static boolean matchPath(
            String pattern, String str, boolean isCaseSensitive) {
        return matchPath(pattern, str, File.separator, isCaseSensitive);
    }

    public static boolean matchPath(
            String pattern, String str, String separator, boolean isCaseSensitive) {
        if ((pattern.length() > (REGEX_HANDLER_PREFIX.length() + PATTERN_HANDLER_SUFFIX.length() + 1))
                && pattern.startsWith(REGEX_HANDLER_PREFIX)
                && pattern.endsWith(PATTERN_HANDLER_SUFFIX)) {
            pattern = pattern.substring(REGEX_HANDLER_PREFIX.length(), pattern.length() - PATTERN_HANDLER_SUFFIX.length());
            return str.matches(pattern);
        } else {
            if ((pattern.length() > (ANT_HANDLER_PREFIX.length() + PATTERN_HANDLER_SUFFIX.length() + 1))
                    && pattern.startsWith(ANT_HANDLER_PREFIX)
                    && pattern.endsWith(PATTERN_HANDLER_SUFFIX)) {
                pattern = pattern.substring(ANT_HANDLER_PREFIX.length(), pattern.length() - PATTERN_HANDLER_SUFFIX.length());
            }

            return matchAntPathPattern(pattern, str, separator, isCaseSensitive);
        }
    }

    public static boolean matchAntPathPattern(
            String pattern, String str, boolean isCaseSensitive) {
        return matchAntPathPattern(pattern, str, File.separator, isCaseSensitive);
    }

    public static boolean matchAntPathPattern(
            String pattern, String str, String separator, boolean isCaseSensitive) {
        // When str starts with a file separator, pattern has to start with a
        // file separator.
        // When pattern starts with a file separator, str has to start with a
        // file separator.
        if (str.startsWith(separator) != pattern.startsWith(separator)) {
            return false;
        }

        List<String> patDirs = tokenizePath(pattern, separator);
        List<String> strDirs = tokenizePath(str, separator);

        int patIdxStart = 0;
        int patIdxEnd = patDirs.size() - 1;
        int strIdxStart = 0;
        int strIdxEnd = strDirs.size() - 1;

        // up to first '**'
        while (patIdxStart <= patIdxEnd && strIdxStart <= strIdxEnd) {
            String patDir = patDirs.get(patIdxStart);
            if (patDir.equals("**")) {
                break;
            }

            String subDir = strDirs.get(strIdxStart);
            if (!match(patDir, subDir, isCaseSensitive)) {
                patDirs = null;
                strDirs = null;
                return false;
            }

            patIdxStart++;
            strIdxStart++;
        }

        if (strIdxStart > strIdxEnd) {
            // String is exhausted
            for (int i = patIdxStart; i <= patIdxEnd; i++) {
                String subPat = patDirs.get(i);
                if (!subPat.equals("**")) {
                    patDirs = null;
                    strDirs = null;
                    return false;
                }
            }
            return true;
        } else {
            if (patIdxStart > patIdxEnd) {
                // String not exhausted, but pattern is. Failure.
                patDirs = null;
                strDirs = null;
                return false;
            }
        }

        // up to last '**'
        while (patIdxStart <= patIdxEnd && strIdxStart <= strIdxEnd) {
            String patDir = patDirs.get(patIdxEnd);
            if (patDir.equals("**")) {
                break;
            }

            String subDir = strDirs.get(strIdxEnd);
            if (!match(patDir, subDir, isCaseSensitive)) {
                patDirs = null;
                strDirs = null;
                return false;
            }

            patIdxEnd--;
            strIdxEnd--;
        }

        if (strIdxStart > strIdxEnd) {
            // String is exhausted
            for (int i = patIdxStart; i <= patIdxEnd; i++) {
                String subPat = patDirs.get(i);
                if (!subPat.equals("**")) {
                    patDirs = null;
                    strDirs = null;
                    return false;
                }
            }
            return true;
        }

        while (patIdxStart != patIdxEnd && strIdxStart <= strIdxEnd) {
            int patIdxTmp = -1;
            for (int i = patIdxStart + 1; i <= patIdxEnd; i++) {
                String subPat = patDirs.get(i);
                if (subPat.equals("**")) {
                    patIdxTmp = i;
                    break;
                }
            }
            if (patIdxTmp == patIdxStart + 1) {
                // '**/**' situation, so skip one
                patIdxStart++;
                continue;
            }
            // Find the pattern between padIdxStart & padIdxTmp in str between
            // strIdxStart & strIdxEnd
            int patLength = patIdxTmp - patIdxStart - 1;
            int strLength = strIdxEnd - strIdxStart + 1;
            int foundIdx = -1;
            strLoop: for (int i = 0; i <= strLength - patLength; i++) {
                for (int j = 0; j < patLength; j++) {
                    String subPat = patDirs.get(patIdxStart + j + 1);
                    String subStr = strDirs.get(strIdxStart + i + j);
                    if (!match(subPat, subStr, isCaseSensitive)) {
                        continue strLoop;
                    }
                }

                foundIdx = strIdxStart + i;
                break;
            }

            if (foundIdx == -1) {
                patDirs = null;
                strDirs = null;
                return false;
            }

            patIdxStart = patIdxTmp;
            strIdxStart = foundIdx + patLength;
        }

        for (int i = patIdxStart; i <= patIdxEnd; i++) {
            String subPat = patDirs.get(i);
            if (!subPat.equals("**")) {
                patDirs = null;
                strDirs = null;
                return false;
            }
        }

        return true;
    }

    /**
     * Tests whether or not a string matches against a pattern. The pattern may contain two special characters:<br>
     * '*' means zero or more characters<br>
     * '?' means one and only one character
     *
     * @param  pattern The pattern to match against. Must not be {@code null}.
     * @param  str     The string which must be matched against the pattern. Must not be {@code null}.
     * @return         <code>true</code> if the string matches against the pattern, or <code>false</code> otherwise.
     */
    public static boolean match(String pattern, String str) {
        return match(pattern, str, true);
    }

    /**
     * Tests whether or not a string matches against a pattern. The pattern may contain two special characters:<br>
     * '*' means zero or more characters<br>
     * '?' means one and only one character
     *
     * @param  pattern         The pattern to match against. Must not be {@code null}.
     * @param  str             The string which must be matched against the pattern. Must not be {@code null}.
     * @param  isCaseSensitive Whether or not matching should be performed case sensitively.
     * @return                 <code>true</code> if the string matches against the pattern, or <code>false</code>
     *                         otherwise.
     */
    @SuppressWarnings("PMD.AssignmentInOperand")
    public static boolean match(String pattern, String str, boolean isCaseSensitive) {
        char[] patArr = pattern.toCharArray();
        char[] strArr = str.toCharArray();
        int patIdxStart = 0;
        int patIdxEnd = patArr.length - 1;
        int strIdxStart = 0;
        int strIdxEnd = strArr.length - 1;
        char ch;

        boolean containsStar = false;
        for (char aPatArr : patArr) {
            if (aPatArr == '*') {
                containsStar = true;
                break;
            }
        }

        if (!containsStar) {
            // No '*'s, so we make a shortcut
            if (patIdxEnd != strIdxEnd) {
                return false; // Pattern and string do not have the same size
            }
            for (int i = 0; i <= patIdxEnd; i++) {
                ch = patArr[i];
                if ((ch != '?') && (!equals(ch, strArr[i], isCaseSensitive))) {
                    return false; // Character mismatch
                }
            }
            return true; // String matches against pattern
        }

        if (patIdxEnd == 0) {
            return true; // Pattern contains only '*', which matches anything
        }

        // Process characters before first star
        // CHECKSTYLE:OFF
        while (((ch = patArr[patIdxStart]) != '*') && (strIdxStart <= strIdxEnd)) {
            if ((ch != '?') && (!equals(ch, strArr[strIdxStart], isCaseSensitive))) {
                return false; // Character mismatch
            }
            patIdxStart++;
            strIdxStart++;
        }
        // CHECKSTYLE:ON

        if (strIdxStart > strIdxEnd) {
            // All characters in the string are used. Check if only '*'s are
            // left in the pattern. If so, we succeeded. Otherwise failure.
            for (int i = patIdxStart; i <= patIdxEnd; i++) {
                if (patArr[i] != '*') {
                    return false;
                }
            }
            return true;
        }

        // Process characters after last star
        // CHECKSTYLE:OFF
        while (((ch = patArr[patIdxEnd]) != '*') && (strIdxStart <= strIdxEnd)) {
            if ((ch != '?') && (!equals(ch, strArr[strIdxEnd], isCaseSensitive))) {
                return false; // Character mismatch
            }
            patIdxEnd--;
            strIdxEnd--;
        }
        // CHECKSTYLE:ON

        if (strIdxStart > strIdxEnd) {
            // All characters in the string are used. Check if only '*'s are
            // left in the pattern. If so, we succeeded. Otherwise failure.
            for (int i = patIdxStart; i <= patIdxEnd; i++) {
                if (patArr[i] != '*') {
                    return false;
                }
            }
            return true;
        }

        // process pattern between stars. padIdxStart and patIdxEnd point always to a '*'.
        while ((patIdxStart != patIdxEnd) && (strIdxStart <= strIdxEnd)) {
            int patIdxTmp = -1;
            for (int i = patIdxStart + 1; i <= patIdxEnd; i++) {
                if (patArr[i] == '*') {
                    patIdxTmp = i;
                    break;
                }
            }
            if (patIdxTmp == patIdxStart + 1) {
                // Two stars next to each other, skip the first one.
                patIdxStart++;
                continue;
            }
            // Find the pattern between padIdxStart & padIdxTmp in str between
            // strIdxStart & strIdxEnd
            int patLength = patIdxTmp - patIdxStart - 1;
            int strLength = strIdxEnd - strIdxStart + 1;
            int foundIdx = -1;
            strLoop: for (int i = 0; i <= strLength - patLength; i++) {
                for (int j = 0; j < patLength; j++) {
                    ch = patArr[patIdxStart + j + 1];
                    if (ch != '?' && !equals(ch, strArr[strIdxStart + i + j], isCaseSensitive)) {
                        continue strLoop;
                    }
                }

                foundIdx = strIdxStart + i;
                break;
            }

            if (foundIdx == -1) {
                return false;
            }

            patIdxStart = patIdxTmp;
            strIdxStart = foundIdx + patLength;
        }

        // All characters in the string are used. Check if only '*'s are left
        // in the pattern. If so, we succeeded. Otherwise failure.
        for (int i = patIdxStart; i <= patIdxEnd; i++) {
            if (patArr[i] != '*') {
                return false;
            }
        }
        return true;
    }

    /**
     * Tests whether two characters are equal.
     *
     * @param  c1              1st character
     * @param  c2              2nd character
     * @param  isCaseSensitive Whether to compare case sensitive
     * @return                 {@code true} if equal characters
     */
    public static boolean equals(char c1, char c2, boolean isCaseSensitive) {
        if (c1 == c2) {
            return true;
        }
        if (!isCaseSensitive) {
            // NOTE: Try both upper case and lower case as done by String.equalsIgnoreCase()
            if (Character.toUpperCase(c1) == Character.toUpperCase(c2)
                    || Character.toLowerCase(c1) == Character.toLowerCase(c2)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Breaks a path up into a Vector of path elements, tokenizing on <code>File.separator</code>.
     *
     * @param  path Path to tokenize. Must not be {@code null}.
     * @return      a List of path elements from the tokenized path
     */
    public static List<String> tokenizePath(String path) {
        return tokenizePath(path, File.separator);
    }

    public static List<String> tokenizePath(String path, String separator) {
        List<String> ret = new ArrayList<>();
        StringTokenizer st = new StringTokenizer(path, separator);
        while (st.hasMoreTokens()) {
            ret.add(st.nextToken());
        }
        return ret;
    }

    /**
     * /** Converts a path to one matching the target file system by applying the &quot;slashification&quot; rules,
     * converting it to a local path and then translating its separator to the target file system one (if different than
     * local one)
     *
     * @param  path          The input path
     * @param  pathSeparator The separator used to build the input path
     * @param  fs            The target {@link FileSystem} - may not be {@code null}
     * @return               The transformed path
     * @see                  #translateToLocalFileSystemPath(String, char, String)
     */
    public static String translateToLocalFileSystemPath(String path, char pathSeparator, FileSystem fs) {
        return translateToLocalFileSystemPath(path, pathSeparator,
                Objects.requireNonNull(fs, "No target file system").getSeparator());
    }

    /**
     * Converts a path to one matching the target file system by applying the &quot;slashification&quot; rules,
     * converting it to a local path and then translating its separator to the target file system one (if different than
     * local one)
     *
     * @param  path          The input path
     * @param  pathSeparator The separator used to build the input path
     * @param  fsSeparator   The target file system separator
     * @return               The transformed path
     * @see                  #applySlashifyRules(String, char)
     * @see                  #translateToLocalPath(String)
     * @see                  #translateToFileSystemPath(String, String, String)
     */
    public static String translateToLocalFileSystemPath(String path, char pathSeparator, String fsSeparator) {
        // In case double slashes and other patterns are used
        String slashified = applySlashifyRules(path, pathSeparator);
        // In case we are running on Windows
        String localPath = translateToLocalPath(slashified);
        return translateToFileSystemPath(localPath, File.separator, fsSeparator);
    }

    /**
     * Applies the &quot;slashification&quot; rules as specified in
     * <A HREF="http://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap03.html#tag_03_266">Single Unix
     * Specification version 3, section 3.266</A> and
     * <A HREF="http://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap04.html#tag_04_11">section 4.11 -
     * Pathname resolution</A>
     *
     * @param  path    The original path - ignored if {@code null}/empty or does not contain any slashes
     * @param  sepChar The &quot;slash&quot; character
     * @return         The effective path - may be same as input if no changes required
     */
    public static String applySlashifyRules(String path, char sepChar) {
        if (GenericUtils.isEmpty(path)) {
            return path;
        }

        int curPos = path.indexOf(sepChar);
        if (curPos < 0) {
            return path; // no slashes to handle
        }

        int lastPos = 0;
        StringBuilder sb = null;
        while (curPos < path.length()) {
            curPos++; // skip the 1st '/'

            /*
             * As per Single Unix Specification version 3, section 3.266:
             *
             * Multiple successive slashes are considered to be the same as one slash
             */
            int nextPos = curPos;
            while ((nextPos < path.length()) && (path.charAt(nextPos) == sepChar)) {
                nextPos++;
            }

            /*
             * At this stage, nextPos is the first non-slash character after a possibly 'seqLen' sequence of consecutive
             * slashes.
             */
            int seqLen = nextPos - curPos;
            if (seqLen > 0) {
                if (sb == null) {
                    sb = new StringBuilder(path.length() - seqLen);
                }

                if (lastPos < curPos) {
                    String clrText = path.substring(lastPos, curPos);
                    sb.append(clrText);
                }

                lastPos = nextPos;
            }

            if (nextPos >= path.length()) {
                break; // no more data
            }

            curPos = path.indexOf(sepChar, nextPos);
            if (curPos < nextPos) {
                break; // no more slashes
            }
        }

        // check if any leftovers for the modified path
        if (sb != null) {
            if (lastPos < path.length()) {
                String clrText = path.substring(lastPos);
                sb.append(clrText);
            }

            path = sb.toString();
        }

        /*
         * At this point we know for sure that 'path' contains only SINGLE slashes. According to section 4.11 - Pathname
         * resolution
         *
         * A pathname that contains at least one non-slash character and that ends with one or more trailing slashes
         * shall be resolved as if a single dot character ( '.' ) were appended to the pathname.
         */
        if ((path.length() > 1) && (path.charAt(path.length() - 1) == sepChar)) {
            return path + ".";
        } else {
            return path;
        }
    }

    /**
     * Converts a possibly '/' separated path to a local path. <B>Note:</B> takes special care of Windows drive paths -
     * e.g., {@code C:} by converting them to &quot;C:\&quot;
     *
     * @param  path The original path - ignored if {@code null}/empty
     * @return      The local path
     */
    public static String translateToLocalPath(String path) {
        if (GenericUtils.isEmpty(path) || (File.separatorChar == '/')) {
            return path;
        }

        // This code is reached if we are running on Windows
        String localPath = path.replace('/', File.separatorChar);
        // check if '/c:' prefix
        if ((localPath.charAt(0) == File.separatorChar) && isWindowsDriveSpecified(localPath, 1, localPath.length() - 1)) {
            localPath = localPath.substring(1);
        }
        if (!isWindowsDriveSpecified(localPath)) {
            return localPath; // assume a relative path
        }

        /*
         * Here we know that we have at least a "C:" string - make sure it is followed by the local file separator.
         * Note: if all we have is just the drive, we will create a "C:\" path since this is the preferred Windows way
         * to refer to root drives in the file system
         */
        if (localPath.length() == 2) {
            return localPath + File.separator; // all we have is "C:"
        } else if (localPath.charAt(2) != File.separatorChar) {
            // be nice and add the missing file separator - C:foo => C:\foo
            return localPath.substring(0, 2) + File.separator + localPath.substring(2);
        } else {
            return localPath;
        }
    }

    public static boolean isWindowsDriveSpecified(CharSequence cs) {
        return isWindowsDriveSpecified(cs, 0, GenericUtils.length(cs));
    }

    public static boolean isWindowsDriveSpecified(CharSequence cs, int offset, int len) {
        if ((len < 2) || (cs.charAt(offset + 1) != ':')) {
            return false;
        }

        char drive = cs.charAt(offset);
        return ((drive >= 'a') && (drive <= 'z')) || ((drive >= 'A') && (drive <= 'Z'));
    }

    /**
     * Converts a path containing a specific separator to one using the specified file-system one
     *
     * @param  path          The input path - ignored if {@code null}/empty
     * @param  pathSeparator The separator used to build the input path - may not be {@code null}/empty
     * @param  fs            The target {@link FileSystem} - may not be {@code null}
     * @return               The path where the separator used to build it is replaced by the file-system one (if
     *                       different)
     * @see                  FileSystem#getSeparator()
     * @see                  #translateToFileSystemPath(String, String, String)
     */
    public static String translateToFileSystemPath(String path, String pathSeparator, FileSystem fs) {
        return translateToFileSystemPath(path, pathSeparator,
                Objects.requireNonNull(fs, "No target file system").getSeparator());
    }

    /**
     * Converts a path containing a specific separator to one using the specified file-system one
     *
     * @param  path                     The input path - ignored if {@code null}/empty
     * @param  pathSeparator            The separator used to build the input path - may not be {@code null}/empty
     * @param  fsSeparator              The target file system separator - may not be {@code null}/empty
     * @return                          The path where the separator used to build it is replaced by the file-system one
     *                                  (if different)
     * @throws IllegalArgumentException if path or file-system separator are {@code null}/empty or if the separators are
     *                                  different and the path contains the target file-system separator as it would
     *                                  create an ambiguity
     */
    public static String translateToFileSystemPath(String path, String pathSeparator, String fsSeparator) {
        ValidateUtils.checkNotNullAndNotEmpty(pathSeparator, "Missing path separator");
        ValidateUtils.checkNotNullAndNotEmpty(fsSeparator, "Missing file-system separator");

        if (GenericUtils.isEmpty(path) || Objects.equals(pathSeparator, fsSeparator)) {
            return path;
        }

        // make sure path does not contain the target separator
        if (path.contains(fsSeparator)) {
            ValidateUtils.throwIllegalArgumentException(
                    "File system replacement may yield ambiguous result for %s with separator=%s", path, fsSeparator);
        }

        // check most likely case
        if ((pathSeparator.length() == 1) && (fsSeparator.length() == 1)) {
            return path.replace(pathSeparator.charAt(0), fsSeparator.charAt(0));
        } else {
            return path.replace(pathSeparator, fsSeparator);
        }
    }

    /**
     * Creates a single path by concatenating 2 parts and taking care not to create FS separator duplication in the
     * process
     *
     * @param  p1          prefix part - ignored if {@code null}/empty
     * @param  p2          suffix part - ignored if {@code null}/empty
     * @param  fsSeparator The expected file-system separator
     * @return             Concatenation result
     */
    public static String concatPaths(String p1, String p2, char fsSeparator) {
        if (GenericUtils.isEmpty(p1)) {
            return p2;
        } else if (GenericUtils.isEmpty(p2)) {
            return p1;
        } else if (p1.charAt(p1.length() - 1) == fsSeparator) {
            if (p2.charAt(0) == fsSeparator) {
                return (p2.length() == 1) ? p1 : p1 + p2.substring(1); // a/b/c/  + /d/e/f
            } else {
                return p1 + p2;     // a/b/c/ + d/e/f
            }
        } else if (p2.charAt(0) == fsSeparator) {
            return (p2.length() == 1) ? p1 : p1 + p2; // /a/b/c + /d/e/f
        } else {
            return p1 + Character.toString(fsSeparator) + p2;    // /a/b/c + d/e/f
        }
    }

    /**
     * "Flattens" a string by removing all whitespace (space, tab, line-feed, carriage return, and form-feed). This uses
     * StringTokenizer and the default set of tokens as documented in the single argument constructor.
     *
     * @param  input a String to remove all whitespace.
     * @return       a String that has had all whitespace removed.
     */
    public static String removeWhitespace(String input) {
        StringBuilder result = new StringBuilder();
        if (input != null) {
            StringTokenizer st = new StringTokenizer(input);
            while (st.hasMoreTokens()) {
                result.append(st.nextToken());
            }
        }
        return result.toString();
    }
}
