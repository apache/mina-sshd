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
package org.apache.sshd.client.session.proxy;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * A basic parser for HTTP response headers. Handles status lines and authentication headers (WWW-Authenticate,
 * Proxy-Authenticate).
 *
 * @see <a href="https://tools.ietf.org/html/rfc7230">RFC 7230</a>
 * @see <a href="https://tools.ietf.org/html/rfc7235">RFC 7235</a>
 */
public final class HttpParser {

    /**
     * An exception indicating some problem parsing HTPP headers.
     */
    public static class ParseException extends Exception {

        private static final long serialVersionUID = -1634090143702048640L;

        /**
         * Creates a new {@link ParseException} without cause.
         */
        public ParseException() {
            super();
        }

        /**
         * Creates a new {@link ParseException} with the given {@code cause}.
         *
         * @param cause {@link Throwable} that caused this exception, or {@code null} if none
         */
        public ParseException(Throwable cause) {
            super(cause);
        }
    }

    private HttpParser() {
        // No instantiation
    }

    /**
     * Parse a HTTP response status line.
     *
     * @param  line           to parse
     * @return                the {@link StatusLine}
     * @throws ParseException if the line cannot be parsed or has the wrong HTTP version
     */
    public static StatusLine parseStatusLine(String line) throws ParseException {
        // Format is HTTP/<version> Code Reason
        int firstBlank = line.indexOf(' ');
        if (firstBlank < 0) {
            throw new ParseException();
        }
        int secondBlank = line.indexOf(' ', firstBlank + 1);
        if (secondBlank < 0) {
            // Accept the line even if the (according to RFC 2616 mandatory)
            // reason is missing.
            secondBlank = line.length();
        }
        int resultCode;
        try {
            resultCode = Integer.parseUnsignedInt(line.substring(firstBlank + 1, secondBlank));
        } catch (NumberFormatException e) {
            throw new ParseException(e);
        }
        // Again, accept even if the reason is missing
        String reason = ""; //$NON-NLS-1$
        if (secondBlank < line.length()) {
            reason = line.substring(secondBlank + 1);
        }
        return new StatusLine(line.substring(0, firstBlank), resultCode, reason);
    }

    /**
     * Extract the authentication headers from the header lines. It is assumed that the first element in {@code reply}
     * is the raw status line as received from the server. It is skipped. Line processing stops on the first empty line
     * thereafter.
     *
     * @param  reply                The complete (header) lines of the HTTP response
     * @param  authenticationHeader to look for (including the terminating ':'!)
     * @return                      a list of {@link AuthenticationChallenge}s found.
     */
    public static List<AuthenticationChallenge> getAuthenticationHeaders(List<String> reply, String authenticationHeader) {
        List<AuthenticationChallenge> challenges = new ArrayList<>();
        Iterator<String> lines = reply.iterator();
        // We know we have at least one line. Skip the response line.
        lines.next();
        StringBuilder value = null;
        while (lines.hasNext()) {
            String line = lines.next();
            if (line.isEmpty()) {
                break;
            }
            if (Character.isWhitespace(line.charAt(0))) {
                // Continuation line.
                if (value == null) {
                    // Skip if we have no current value
                    continue;
                }
                // Skip leading whitespace
                int i = skipWhiteSpace(line, 1);
                value.append(' ').append(line, i, line.length());
                continue;
            }
            if (value != null) {
                parseChallenges(challenges, value.toString());
                value = null;
            }
            int firstColon = line.indexOf(':');
            if (firstColon > 0 && authenticationHeader.equalsIgnoreCase(line.substring(0, firstColon + 1))) {
                value = new StringBuilder(line.substring(firstColon + 1));
            }
        }
        if (value != null) {
            parseChallenges(challenges, value.toString());
        }
        return challenges;
    }

    private static void parseChallenges(List<AuthenticationChallenge> challenges, String header) {
        // Comma-separated list of challenges, each itself a scheme name
        // followed optionally by either: a comma-separated list of key=value
        // pairs, where the value may be a quoted string with backslash escapes,
        // or a single token value, which itself may end in zero or more '='
        // characters. Ugh.
        int length = header.length();
        for (int i = 0; i < length;) {
            int start = skipWhiteSpace(header, i);
            int end = scanToken(header, start);
            if (end <= start) {
                break;
            }
            AuthenticationChallenge challenge = new AuthenticationChallenge(header.substring(start, end));
            challenges.add(challenge);
            i = parseChallenge(challenge, header, end);
        }
    }

    private static int parseChallenge(AuthenticationChallenge challenge, String header, int from) {
        int length = header.length();
        boolean first = true;
        for (int start = from; start <= length; first = false) {
            // Now we have either a single token, which may end in zero or more
            // equal signs, or a comma-separated list of key=value pairs (with
            // optional legacy whitespace around the equals sign), where the
            // value can be either a token or a quoted string.
            start = skipWhiteSpace(header, start);
            int end = scanToken(header, start);
            if (end == start) {
                // Nothing found. Either at end or on a comma.
                if (start < header.length() && header.charAt(start) == ',') {
                    return start + 1;
                }
                return start;
            }
            int next = skipWhiteSpace(header, end);
            // Comma, or equals sign, or end of string
            if (next >= length || header.charAt(next) != '=') {
                if (first) {
                    // It must be a token
                    challenge.setToken(header.substring(start, end));
                    if (next < length && header.charAt(next) == ',') {
                        next++;
                    }
                    return next;
                }
                // This token must be the name of the next authentication
                // scheme.
                return start;
            }
            int nextStart = skipWhiteSpace(header, next + 1);
            if (nextStart >= length) {
                if (next == end) {
                    // '=' immediately after the key, no value: key must be the
                    // token, and the equals sign is part of the token
                    challenge.setToken(header.substring(start, end + 1));
                } else {
                    // Key without value...
                    challenge.addArgument(header.substring(start, end), null);
                }
                return nextStart;
            }
            if (nextStart == end + 1 && header.charAt(nextStart) == '=') {
                // More than one equals sign: must be the single token.
                end = nextStart + 1;
                while (end < length && header.charAt(end) == '=') {
                    end++;
                }
                challenge.setToken(header.substring(start, end));
                end = skipWhiteSpace(header, end);
                if (end < length && header.charAt(end) == ',') {
                    end++;
                }
                return end;
            }
            if (header.charAt(nextStart) == ',') {
                if (next == end) {
                    // '=' immediately after the key, no value: key must be the
                    // token, and the equals sign is part of the token
                    challenge.setToken(header.substring(start, end + 1));
                    return nextStart + 1;
                }
                // Key without value...
                challenge.addArgument(header.substring(start, end), null);
                start = nextStart + 1;
            } else {
                if (header.charAt(nextStart) == '"') {
                    int[] nextEnd = { nextStart + 1 };
                    String value = scanQuotedString(header, nextStart + 1, nextEnd);
                    challenge.addArgument(header.substring(start, end), value);
                    start = nextEnd[0];
                } else {
                    int nextEnd = scanToken(header, nextStart);
                    challenge.addArgument(header.substring(start, end), header.substring(nextStart, nextEnd));
                    start = nextEnd;
                }
                start = skipWhiteSpace(header, start);
                if (start < length && header.charAt(start) == ',') {
                    start++;
                }
            }
        }
        return length;
    }

    private static int skipWhiteSpace(String header, int i) {
        int length = header.length();
        while (i < length && Character.isWhitespace(header.charAt(i))) {
            i++;
        }
        return i;
    }

    private static String scanQuotedString(String header, int from, int[] to) {
        StringBuilder result = new StringBuilder();
        int length = header.length();
        boolean quoted = false;
        int i = from;
        while (i < length) {
            char c = header.charAt(i++);
            if (quoted) {
                result.append(c);
                quoted = false;
            } else if (c == '\\') {
                quoted = true;
            } else if (c == '"') {
                break;
            } else {
                result.append(c);
            }
        }
        to[0] = i;
        return result.toString();
    }

    /**
     * Scan a RFC 7230 token as it appears in HTTP headers.
     *
     * @param  header                    to scan in
     * @param  from                      index in {@code header} to start scanning at
     * @return                           the index after the token, that is, on the first non-token character or
     *                                   {@code header.length}
     * @throws IndexOutOfBoundsException if {@code from < 0} or {@code from > header.length()}
     *
     * @see                              <a href="https://tools.ietf.org/html/rfc7230#appendix-B">RFC 7230, Appendix B:
     *                                   Collected Grammar; "token" production</a>
     */
    private static int scanToken(String header, int from) {
        int length = header.length();
        int i = from;
        if (i < 0 || i > length) {
            throw new IndexOutOfBoundsException();
        }
        while (i < length) {
            char c = header.charAt(i);
            switch (c) {
                case '!':
                case '#':
                case '$':
                case '%':
                case '&':
                case '\'':
                case '*':
                case '+':
                case '-':
                case '.':
                case '^':
                case '_':
                case '`':
                case '|':
                case '~':
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    i++;
                    break;
                default:
                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                        i++;
                        break;
                    }
                    return i;
            }
        }
        return i;
    }

}
