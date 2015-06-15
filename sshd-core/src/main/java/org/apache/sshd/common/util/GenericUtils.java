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

package org.apache.sshd.common.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public final class GenericUtils {
    public static final byte[]      EMPTY_BYTE_ARRAY={ };
    public static final String[]    EMPTY_STRING_ARRAY={ };
    public static final Object[]    EMPTY_OBJECT_ARRAY={ };

    private GenericUtils() {
        throw new UnsupportedOperationException("No instance");
    }

    public static final String trimToEmpty(String s) {
        if (s == null) {
            return "";
        } else {
            return s.trim();
        }
    }

    public static final int safeCompare(String s1, String s2, boolean caseSensitive) {
        if (s1 == s2) {
            return 0;
        } else if (s1 == null) {
            return (+1);    // push null(s) to end
        } else if (s2 == null) {
            return (-1);    // push null(s) to end
        } else if (caseSensitive) {
            return s1.compareTo(s2);
        } else {
            return s1.compareToIgnoreCase(s2);
        }
    }

    public static final int length(CharSequence cs) {
        if (cs == null) {
            return 0;
        } else {
            return cs.length();
        }
    }

    public static final boolean isEmpty(CharSequence cs) {
        if (length(cs) <= 0) {
            return true;
        } else {
            return false;
        }
    }

    // a List would be better, but we want to be compatible with String.split(...)
    public static final String[] split(String s, char ch) {
        if (isEmpty(s)) {
            return EMPTY_STRING_ARRAY;
        }
        
        int lastPos=0, curPos=s.indexOf(ch);
        if (curPos < 0) {
            return new String[] { s };
        }
        
        Collection<String>  values=new LinkedList<String>();
        do {
            String  v=s.substring(lastPos, curPos);
            values.add(v);
            
            // skip separator
            if ((lastPos = curPos + 1) >= s.length()) {
                break;
            }
            
            if ((curPos = s.indexOf(ch, lastPos)) < lastPos) {
                break;  // no more separators
            }
        } while(curPos < s.length());
        
        // check if any leftovers
        if (lastPos < s.length()) {
            String  v=s.substring(lastPos);
            values.add(v);
        }

        return values.toArray(new String[values.size()]);
    }

    public static final <T> String join(T[] values, char ch) {
        return join(isEmpty(values) ? Collections.<T>emptyList() : Arrays.asList(values), ch);
    }

    public static final String join(Iterable<?> iter, char ch) {
        return join((iter == null) ? null : iter.iterator(), ch);
    }
    
    public static final String join(Iterator<?> iter, char ch) {
        if ((iter == null) || (!iter.hasNext())) {
            return "";
        }
        
        StringBuilder   sb=new StringBuilder();
        do {    // we already asked hasNext...
            Object  o=iter.next();
            if (sb.length() > 0) {
                sb.append(ch);
            }
            sb.append(Objects.toString(o));
        } while(iter.hasNext());
        
        return sb.toString();
    }

    public static final <T> String join(T[] values, CharSequence sep) {
        return join(isEmpty(values) ? Collections.<T>emptyList() : Arrays.asList(values), sep);
    }

    public static final String join(Iterable<?> iter, CharSequence sep) {
        return join((iter == null) ? null : iter.iterator(), sep);
    }
    
    public static final String join(Iterator<?> iter, CharSequence sep) {
        if ((iter == null) || (!iter.hasNext())) {
            return "";
        }
        
        StringBuilder   sb=new StringBuilder();
        do {    // we already asked hasNext...
            Object  o=iter.next();
            if (sb.length() > 0) {
                sb.append(sep);
            }
            sb.append(Objects.toString(o));
        } while(iter.hasNext());
        
        return sb.toString();
    }
    
    public static final int size(Collection<?> c) {
        if (c == null) {
            return 0;
        } else {
            return c.size();
        }
    }

    public static final boolean isEmpty(Collection<?> c) {
        if (size(c) <= 0) {
            return true;
        } else {
            return false;
        }
    }

    public static final int size(Map<?,?> m) {
        if (m == null) {
            return 0;
        } else {
            return m.size();
        }
    }

    public static final boolean isEmpty(Map<?,?> m) {
        if (size(m) <= 0) {
            return true;
        } else {
            return false;
        }
    }

    public static final int length(byte ... a) {
        if (a == null) {
            return 0;
        } else {
            return a.length;
        }
    }

    @SafeVarargs
    public static final <T> int length(T ... a) {
        if (a == null) {
            return 0;
        } else {
            return a.length;
        }
    }

    public static final <T> boolean isEmpty(Iterable<? extends T> iter) {
        if (iter == null) {
            return true;
        } else if (iter instanceof Collection<?>) {
            return isEmpty((Collection<?>) iter);
        } else {
            return isEmpty(iter.iterator());
        }
    }

    public static final <T> boolean isEmpty(Iterator<? extends T> iter) {
        if (iter == null) {
            return true;
        } else if (iter.hasNext()) {
            return false;   // debug breakpoint
        } else {
            return true;
        }
    }

    @SafeVarargs
    public static final <T> boolean isEmpty(T ... a) {
        if (length(a) <= 0) {
            return true;
        } else {
            return false;
        }
    }

    @SafeVarargs    // there is no EnumSet.of(...) so we have to provide our own
    public static final <E extends Enum<E>> Set<E> of(E ... values) {
        return of(isEmpty(values) ? Collections.<E>emptySet() : Arrays.asList(values));
    }

    public static final <E extends Enum<E>> Set<E> of(Collection<? extends E> values) {
        if (isEmpty(values)) {
            return Collections.emptySet();
        }

        Set<E>  result=null;
        for (E v : values) {
            /*
             * A trick to compensate for the fact that we do not have
             * the enum Class to invoke EnumSet.noneOf
             */
            if (result == null) {
                result = EnumSet.of(v);
            } else {
                result.add(v);
            }
        }

        return result;
    }

    @SuppressWarnings("rawtypes")
    private static final Comparator<Comparable> naturalOrderComparator=new Comparator<Comparable>() {
        // TODO for JDK-8 use Comparator.naturalOrder() 
        @Override
        @SuppressWarnings("unchecked")
        public int compare(Comparable c1, Comparable c2) {
            return c1.compareTo(c2);
        }
    };

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static final <V extends Comparable<V>> Comparator<V> naturalComparator() {
        // TODO for JDK-8 use Comparator.naturalOrder() 
        return (Comparator) naturalOrderComparator;
    }

    public static final <V extends Comparable<V>> SortedSet<V> asSortedSet(Collection<? extends V> values) {
        // TODO for JDK-8 use Comparator.naturalOrder() 
        return asSortedSet(GenericUtils.<V>naturalComparator(), values);
    }

    /**
     * @param comp The (non-{@code null}) {@link Comparator} to use
     * @param values The values to be added (ignored if {@code null))
     * @return A {@link SortedSet} containing the values (if any) sorted
     * using the provided comparator
     */
    public static final <V> SortedSet<V> asSortedSet(Comparator<? super V> comp, Collection<? extends V> values) {
        // TODO for JDK-8 return Collections.emptySortedSet()
        SortedSet<V>    set=new TreeSet<V>(ValidateUtils.checkNotNull(comp, "No comparator", EMPTY_OBJECT_ARRAY));
        if (size(values) > 0) {
            set.addAll(values);
        }
        
        return set;
    }
    
    public static final String QUOTES="\"'";

    /**
     * @param s The {@link CharSequence} to be checked
     * @return If the sequence contains any of the {@link #QUOTES}
     * on <U>both</U> ends, then they are stripped, otherwise
     * nothing is done
     * @see #stripDelimiters(CharSeqeuence, char)
     */
    public static final CharSequence stripQuotes(CharSequence s) {
        if (isEmpty(s)) {
            return s;
        }
        
        for (int index=0; index < QUOTES.length(); index++) {
            char delim = QUOTES.charAt(index);
            CharSequence v = stripDelimiters(s, delim);
            if (v != s) {   // if stripped one don't continue
                return v;
            }
        }
        
        return s;
    }

    /**
     * @param s The {@link CharSequence} to be checked
     * @param delim The expected delimiter
     * @return If the sequence contains the delimiter on <U>both</U> ends,
     * then it is are stripped, otherwise nothing is done
     */
    public static final CharSequence stripDelimiters(CharSequence s, char delim) {
        if (isEmpty(s) || (s.length() < 2)) {
            return s;
        }
        
        int lastPos = s.length() - 1;
        if ((s.charAt(0) != delim) || (s.charAt(lastPos) != delim)) {
            return s;
        } else {
            return s.subSequence(1, lastPos);
        }
    }
    
    /**
     * Used to &quot;accumulate&quot; exceptions of the <U>same type</U>. If the
     * current exception is {@code null} then the new one becomes the current,
     * otherwise the new one is added as a <U>suppressed</U> exception to the
     * current one
     * @param current The current exception
     * @param extra The extra/new exception
     * @return The resolved exception
     * @see Throwable#addSuppressed(Throwable)
     */
    public static <T extends Throwable> T accumulateException(T current, T extra) {
        if (current == null) {
            return extra;
        }
        
        if ((extra == null) || (extra == current)) {
            return current;
        }
        
        current.addSuppressed(extra);
        return current;
    }
}
