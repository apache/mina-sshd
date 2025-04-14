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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * Global repository of GSS-API mechanisms that we can use.
 */
public final class GssApiMechanisms {

    /** Prefix to use with {@link GSSName#NT_HOSTBASED_SERVICE}. */
    public static final String GSSAPI_HOST_PREFIX = "host@"; //$NON-NLS-1$

    /** The {@link Oid} of Kerberos 5. */
    public static final Oid KERBEROS_5 = createOid("1.2.840.113554.1.2.2"); //$NON-NLS-1$

    /** SGNEGO is not to be used with ssh. */
    public static final Oid SPNEGO = createOid("1.3.6.1.5.5.2"); //$NON-NLS-1$

    /** Protects {@link #supportedMechanisms}. */
    private static final Object LOCK = new Object();

    /**
     * The {@link AtomicBoolean} is set to {@code true} when the mechanism could be initialized successfully at least
     * once.
     */
    private static Map<Oid, Boolean> supportedMechanisms;

    private GssApiMechanisms() {
        // No instantiation
    }

    /**
     * Retrieves an immutable collection of the supported mechanisms.
     *
     * @return the supported mechanisms
     */
    public static Collection<Oid> getSupportedMechanisms() {
        synchronized (LOCK) {
            if (supportedMechanisms == null) {
                GSSManager manager = GSSManager.getInstance();
                Oid[] mechs = manager.getMechs();
                Map<Oid, Boolean> mechanisms = new LinkedHashMap<>();
                if (mechs != null) {
                    for (Oid oid : mechs) {
                        mechanisms.put(oid, Boolean.FALSE);
                    }
                }
                supportedMechanisms = mechanisms;
            }
            return Collections.unmodifiableSet(supportedMechanisms.keySet());
        }
    }

    /**
     * Report that this mechanism was used successfully.
     *
     * @param mechanism that worked
     */
    public static void worked(Oid mechanism) {
        synchronized (LOCK) {
            supportedMechanisms.put(mechanism, Boolean.TRUE);
        }
    }

    /**
     * Mark the mechanisms as failed.
     *
     * @param mechanism to mark
     */
    public static void failed(Oid mechanism) {
        synchronized (LOCK) {
            Boolean worked = supportedMechanisms.get(mechanism);
            if (worked != null && !worked.booleanValue()) {
                // If it never worked, remove it
                supportedMechanisms.remove(mechanism);
            }
        }
    }

    /**
     * Resolves an {@link InetSocketAddress}.
     *
     * @param  remote to resolve
     * @return        the resolved {@link InetAddress}, or {@code null} if unresolved.
     */
    public static InetAddress resolve(InetSocketAddress remote) {
        InetAddress address = remote.getAddress();
        if (address == null) {
            try {
                address = InetAddress.getByName(remote.getHostString());
            } catch (UnknownHostException e) {
                return null;
            }
        }
        return address;
    }

    /**
     * Determines a canonical host name for use use with GSS-API.
     *
     * @param  remote to get the host name from
     * @return        the canonical host name, if it can be determined, otherwise the
     *                {@link InetSocketAddress#getHostString() unprocessed host name}.
     */
    public static String getCanonicalName(InetSocketAddress remote) {
        InetAddress address = resolve(remote);
        if (address == null) {
            return remote.getHostString();
        }
        return address.getCanonicalHostName();
    }

    /**
     * Creates a {@link GSSContext} for the given mechanism to authenticate with the host given by {@code fqdn}.
     *
     * @param  mechanism {@link Oid} of the mechanism to use
     * @param  fqdn      fully qualified domain name of the host to authenticate with
     * @return           the context, if the mechanism is available and the context could be created, or {@code null}
     *                   otherwise
     */
    public static GSSContext createContext(Oid mechanism, String fqdn) {
        GSSContext context = null;
        try {
            GSSManager manager = GSSManager.getInstance();
            context = manager.createContext(
                    manager.createName(GssApiMechanisms.GSSAPI_HOST_PREFIX + fqdn, GSSName.NT_HOSTBASED_SERVICE), mechanism,
                    null, GSSContext.DEFAULT_LIFETIME);
        } catch (GSSException e) {
            closeContextSilently(context);
            failed(mechanism);
            return null;
        }
        worked(mechanism);
        return context;
    }

    /**
     * Closes (disposes of) a {@link GSSContext} ignoring any {@link GSSException}s.
     *
     * @param context to dispose
     */
    public static void closeContextSilently(GSSContext context) {
        if (context != null) {
            try {
                context.dispose();
            } catch (GSSException e) {
                // Ignore
            }
        }
    }

    private static Oid createOid(String rep) {
        try {
            return new Oid(rep);
        } catch (GSSException e) {
            // Does not occur
            return null;
        }
    }

}
