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

package org.apache.sshd.common.subsystem.sftp.extensions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.sshd.common.subsystem.sftp.extensions.Supported2Parser.Supported2;
import org.apache.sshd.common.subsystem.sftp.extensions.SupportedParser.Supported;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.FstatVfsExtensionParser;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.FsyncExtensionParser;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.HardLinkExtensionParser;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.PosixRenameExtensionParser;
import org.apache.sshd.common.subsystem.sftp.extensions.openssh.StatVfsExtensionParser;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see <A HREF="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">OpenSSH</A> section 3.4
 */
public final class ParserUtils {
    public static final Collection<ExtensionParser<?>> BUILT_IN_PARSERS =
            Collections.unmodifiableList(
                    Arrays.<ExtensionParser<?>>asList(
                            VendorIdParser.INSTANCE,
                            NewlineParser.INSTANCE,
                            VersionsParser.INSTANCE,
                            SupportedParser.INSTANCE,
                            Supported2Parser.INSTANCE,
                            // OpenSSH extensions
                            PosixRenameExtensionParser.INSTANCE,
                            StatVfsExtensionParser.INSTANCE,
                            FstatVfsExtensionParser.INSTANCE,
                            HardLinkExtensionParser.INSTANCE,
                            FsyncExtensionParser.INSTANCE
                    ));

    private static final Map<String,ExtensionParser<?>> parsersMap = new TreeMap<String,ExtensionParser<?>>(String.CASE_INSENSITIVE_ORDER) {
            private static final long serialVersionUID = 1L;    // we're not serializing it
            
            {
                for (ExtensionParser<?> p : BUILT_IN_PARSERS) {
                    put(p.getName(), p);
                }
            }
        };

    /**
     * @param parser The {@link ExtensionParser} to register
     * @return The replaced parser (by name) - {@code null} if no previous parser
     * for this extension name
     */
    public static ExtensionParser<?> registerParser(ExtensionParser<?> parser) {
        ValidateUtils.checkNotNull(parser, "No parser instance", GenericUtils.EMPTY_OBJECT_ARRAY);
        
        synchronized(parsersMap) {
            return parsersMap.put(parser.getName(), parser);
        }
    }

    /**
     * @param name The extension name - ignored if {@code null}/empty
     * @return The removed {@link ExtensionParser} - {@code null} if none registered
     * for this extension name
     */
    public static ExtensionParser<?> unregisterParser(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized(parsersMap) {
            return parsersMap.remove(name);
        }
    }

    /**
     * @param name The extension name - ignored if {@code null}/empty
     * @return The registered {@link ExtensionParser} - {@code null} if none registered
     * for this extension name
     */
    public static ExtensionParser<?> getRegisteredParser(String name) {
        if (GenericUtils.isEmpty(name)) {
            return null;
        }

        synchronized(parsersMap) {
            return parsersMap.get(name);
        }
    }

    public static Set<String> getRegisteredParsersNames() {
        synchronized(parsersMap) {
            if (parsersMap.isEmpty()) {
                return Collections.emptySet();
            } else {    // return a copy in order to avoid concurrent modification issues
                return GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, parsersMap.keySet());
            }
        }
    }

    public static final List<ExtensionParser<?>> getRegisteredParsers() {
        synchronized(parsersMap) {
            if (parsersMap.isEmpty()) {
                return Collections.emptyList();
            } else { // return a copy in order to avoid concurrent modification issues
                return new ArrayList<ExtensionParser<?>>(parsersMap.values());
            }
        }
    }

    public static final Set<String> supportedExtensions(Map<String,?> parsed) {
        if (GenericUtils.isEmpty(parsed)) {
            return Collections.emptySet();
        }
        
        Supported sup = (Supported) parsed.get(SupportedParser.INSTANCE.getName());
        Collection<String> extra = (sup == null) ? null : sup.extensionNames;
        Supported2 sup2 = (Supported2) parsed.get(Supported2Parser.INSTANCE.getName());
        Collection<String> extra2 = (sup2 == null) ? null : sup2.extensionNames;
        if (GenericUtils.isEmpty(extra)) {
            return GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, extra2);
        } else if (GenericUtils.isEmpty(extra2)) {
            return GenericUtils.asSortedSet(String.CASE_INSENSITIVE_ORDER, extra);
        }
        
        Set<String> result = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        result.addAll(extra);
        result.addAll(extra2);
        return result;
    }

    /**
     * @param extensions The received extensions in encoded form
     * @return A {@link Map} of all the successfully decoded extensions
     * where key=extension name (same as in the original map), value=the
     * decoded extension value. Extensions for which there is no registered
     * parser are <U>ignored</U>
     * @see #getRegisteredParser(String)
     * @see ExtensionParser#transform(Object)
     */
    public static final Map<String,Object> parse(Map<String,byte[]> extensions) {
        if (GenericUtils.isEmpty(extensions)) {
            return Collections.emptyMap();
        }
        
        Map<String,Object> data = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String,byte[]> ee : extensions.entrySet()) {
            String name = ee.getKey();
            Object result = parse(name, ee.getValue());
            if (result == null) {
                continue;
            }
            data.put(name, result);
        }
        
        return data;
    }

    public static final Object parse(String name, byte ... encoded) {
        ExtensionParser<?> parser = getRegisteredParser(name);
        if (parser == null) {
            return null;
        } else {
            return parser.transform(encoded);
        }
    }
    
    private ParserUtils() {
        throw new UnsupportedOperationException("No instance");
    }
}
