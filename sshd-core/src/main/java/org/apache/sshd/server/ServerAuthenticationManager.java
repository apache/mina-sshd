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

package org.apache.sshd.server;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.keyprovider.KeyPairProviderHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.server.auth.BuiltinUserAuthFactories;
import org.apache.sshd.server.auth.UserAuth;
import org.apache.sshd.server.auth.WelcomeBannerPhase;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.auth.gss.UserAuthGSSFactory;
import org.apache.sshd.server.auth.hostbased.HostBasedAuthenticator;
import org.apache.sshd.server.auth.keyboard.KeyboardInteractiveAuthenticator;
import org.apache.sshd.server.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;

/**
 * Holds providers and helpers related to the server side authentication process
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface ServerAuthenticationManager extends KeyPairProviderHolder {
    /**
     * Key used to retrieve the value in the configuration properties map
     * of the maximum number of failed authentication requests before the
     * server closes the connection.
     * @see #DEFAULT_MAX_AUTH_REQUESTS
     */
    String MAX_AUTH_REQUESTS = "max-auth-requests";

    /**
     * Default value for {@link #MAX_AUTH_REQUESTS} if none configured
     */
    int DEFAULT_MAX_AUTH_REQUESTS = 20;

    /**
     * Key used to retrieve the value of welcome banner that will be displayed
     * when a user connects to the server. If {@code null}/empty then no banner
     * will be sent. The value can be one of the following:
     * <UL>
     *      <P><LI>
     *      A {@link java.io.File} or {@link java.nio.file.Path}, in which case
     *      its contents will be transmitted. <B>Note:</B> if the file is empty
     *      or does not exits, no banner will be transmitted.
     *      </LI></P>
     *
     *      <P><LI>
     *      A {@link java.net.URI} or a string starting with &quot;file:/&quot;, in
     *      which case it will be converted to a {@link java.nio.file.Path} and
     *      handled accordingly.
     *      </LI></P>
     *
     *      <P><LI>
     *      A string containing a special value indicator - e.g., {@link #AUTO_WELCOME_BANNER_VALUE},
     *      in which case the relevant banner content will be generated.
     *      </LI></P>
     *
     *      <P><LI>
     *      Any other object whose {@code toString()} value yields a non empty string
     *      will be used as the banner contents.
     *      </LI></P>
     * </UL>
     * @see <A HREF="https://tools.ietf.org/html/rfc4252#section-5.4">RFC-4252 section 5.4</A>
     */
    String WELCOME_BANNER = "welcome-banner";

    /**
     * Special value that can be set for the {@link #WELCOME_BANNER} property
     * indicating that the server should generate a banner consisting of the
     * random art of the server's keys (if any are provided). If no server
     * keys are available, then no banner will be sent
     */
    String AUTO_WELCOME_BANNER_VALUE = "#auto-welcome-banner";

    /**
     * Key used to denote the language code for the welcome banner (if such
     * a banner is configured). If not set, then {@link ServerAuthenticationManager#DEFAULT_WELCOME_BANNER_LANGUAGE}
     * is used
     */
    String WELCOME_BANNER_LANGUAGE = "welcome-banner-language";

    /**
     * Default value for {@link #WELCOME_BANNER_LANGUAGE} is not overwritten
     */
    String DEFAULT_WELCOME_BANNER_LANGUAGE = "en";

    /**
     * The {@link WelcomeBannerPhase} value - either as an enum or
     * a string
     */
    String WELCOME_BANNER_PHASE = "welcome-banner-phase";

    /**
     * Default value for {@link #WELCOME_BANNER_PHASE} if none specified
     */
    WelcomeBannerPhase DEFAULT_BANNER_PHASE = WelcomeBannerPhase.IMMEDIATE;

    /**
     * The charset to use if the configured welcome banner points
     * to a file - if not specified (either as a string or a {@link java.nio.charset.Charset}
     * then the local default is used.
     */
    String WELCOME_BANNER_CHARSET = "welcome-banner-charset";

    /**
     * This key is used when configuring multi-step authentications.
     * The value needs to be a blank separated list of comma separated list
     * of authentication method names.
     * For example, an argument of
     * <code>publickey,password publickey,keyboard-interactive</code>
     * would require the user to complete public key authentication,
     * followed by either password or keyboard interactive authentication.
     * Only methods that are next in one or more lists are offered at each
     * stage, so for this example, it would not be possible to attempt
     * password or keyboard-interactive authentication before public key.
     */
    String AUTH_METHODS = "auth-methods";

    UserAuthPublicKeyFactory DEFAULT_USER_AUTH_PUBLIC_KEY_FACTORY = UserAuthPublicKeyFactory.INSTANCE;

    UserAuthGSSFactory DEFAULT_USER_AUTH_GSS_FACTORY = UserAuthGSSFactory.INSTANCE;

    UserAuthPasswordFactory DEFAULT_USER_AUTH_PASSWORD_FACTORY = UserAuthPasswordFactory.INSTANCE;

    UserAuthKeyboardInteractiveFactory DEFAULT_USER_AUTH_KB_INTERACTIVE_FACTORY = UserAuthKeyboardInteractiveFactory.INSTANCE;

    /**
     * Retrieve the list of named factories for <code>UserAuth</code> objects.
     *
     * @return a list of named <code>UserAuth</code> factories, never {@code null}/empty
     */
    List<NamedFactory<UserAuth>> getUserAuthFactories();

    default String getUserAuthFactoriesNameList() {
        return NamedResource.getNames(getUserAuthFactories());
    }

    default List<String> getUserAuthFactoriesNames() {
        return NamedResource.getNameList(getUserAuthFactories());
    }

    void setUserAuthFactories(List<NamedFactory<UserAuth>> userAuthFactories);

    default void setUserAuthFactoriesNameList(String names) {
        setUserAuthFactoriesNames(GenericUtils.split(names, ','));
    }

    default void setUserAuthFactoriesNames(String... names) {
        setUserAuthFactoriesNames(GenericUtils.isEmpty((Object[]) names) ? Collections.emptyList() : Arrays.asList(names));
    }

    default void setUserAuthFactoriesNames(Collection<String> names) {
        BuiltinUserAuthFactories.ParseResult result = BuiltinUserAuthFactories.parseFactoriesList(names);
        @SuppressWarnings({ "rawtypes", "unchecked" })
        List<NamedFactory<UserAuth>> factories =
                (List) ValidateUtils.checkNotNullAndNotEmpty(result.getParsedFactories(), "No supported cipher factories: %s", names);
        Collection<String> unsupported = result.getUnsupportedFactories();
        ValidateUtils.checkTrue(GenericUtils.isEmpty(unsupported), "Unsupported cipher factories found: %s", unsupported);
        setUserAuthFactories(factories);
    }

    /**
     * Retrieve the <code>PublickeyAuthenticator</code> to be used by SSH server.
     * If no authenticator has been configured (i.e. this method returns
     * {@code null}), then client authentication requests based on keys will be
     * rejected.
     *
     * @return the {@link PublickeyAuthenticator} or {@code null}
     */
    PublickeyAuthenticator getPublickeyAuthenticator();

    void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator);

    /**
     * Retrieve the <code>PasswordAuthenticator</code> to be used by the SSH server.
     * If no authenticator has been configured (i.e. this method returns
     * {@code null}), then client authentication requests based on passwords
     * will be rejected.
     *
     * @return the {@link PasswordAuthenticator} or {@code null}
     */
    PasswordAuthenticator getPasswordAuthenticator();

    void setPublickeyAuthenticator(PublickeyAuthenticator publickeyAuthenticator);

    /**
     * Retrieve the <code>KeyboardInteractiveAuthenticator</code> to be used by
     * the SSH server. If no authenticator has been configured (i.e. this method returns
     * {@code null}), then client authentication requests based on this method
     * will be rejected.
     *
     * @return The {@link KeyboardInteractiveAuthenticator} or {@code null}
     */
    KeyboardInteractiveAuthenticator getKeyboardInteractiveAuthenticator();

    void setKeyboardInteractiveAuthenticator(KeyboardInteractiveAuthenticator interactiveAuthenticator);

    /**
     * Retrieve the <code>GSSAuthenticator</code> to be used by the SSH server.
     * If no authenticator has been configured (i.e. this method returns
     * {@code null}), then client authentication requests based on gssapi
     * will be rejected.
     *
     * @return the {@link GSSAuthenticator} or {@code null}
     */
    GSSAuthenticator getGSSAuthenticator();

    void setGSSAuthenticator(GSSAuthenticator gssAuthenticator);

    /**
     * Retrieve the {@code HostBasedAuthenticator} to be used by the SSH server. If
     * no authenticator has been configured (i.e. this method returns {@code null}),
     * then client authentication requests based on this method will be rejected.
     *
     * @return the {@link HostBasedAuthenticator} or {@code null}
     */
    HostBasedAuthenticator getHostBasedAuthenticator();

    void setHostBasedAuthenticator(HostBasedAuthenticator hostBasedAuthenticator);

    /**
     * If user authentication factories already set, then simply returns them. Otherwise,
     * builds the factories list from the individual authenticators available for
     * the manager - password public key, keyboard-interactive, GSS, etc...
     *
     * @param manager The {@link ServerAuthenticationManager} - ignored if {@code null}
     * @return The resolved {@link List} of {@link NamedFactory} for the {@link UserAuth}s
     * @see #resolveUserAuthFactories(ServerAuthenticationManager, List)
     */
    static List<NamedFactory<UserAuth>> resolveUserAuthFactories(ServerAuthenticationManager manager) {
        if (manager == null) {
            return Collections.emptyList();
        } else {
            return resolveUserAuthFactories(manager, manager.getUserAuthFactories());
        }
    }

    /**
     * If user authentication factories already set, then simply returns them. Otherwise,
     * builds the factories list from the individual authenticators available for
     * the manager - password public key, keyboard-interactive, GSS, etc...
     *
     * @param manager The {@link ServerAuthenticationManager} - ignored if {@code null}
     * @param userFactories The currently available {@link UserAuth} factories - if not
     * {@code null}/empty then they are used as-is.
     * @return The resolved {@link List} of {@link NamedFactory} for the {@link UserAuth}s
     */
    static List<NamedFactory<UserAuth>> resolveUserAuthFactories(
            ServerAuthenticationManager manager, List<NamedFactory<UserAuth>> userFactories) {
        if (GenericUtils.size(userFactories) > 0) {
            return userFactories;   // use whatever the user decided
        }

        if (manager == null) {
            return Collections.emptyList();
        }

        List<NamedFactory<UserAuth>> factories = new ArrayList<>();
        if (manager.getPasswordAuthenticator() != null) {
            factories.add(DEFAULT_USER_AUTH_PASSWORD_FACTORY);
            factories.add(DEFAULT_USER_AUTH_KB_INTERACTIVE_FACTORY);
        } else if (manager.getKeyboardInteractiveAuthenticator() != null) {
            factories.add(DEFAULT_USER_AUTH_KB_INTERACTIVE_FACTORY);
        }

        if (manager.getPublickeyAuthenticator() != null) {
            factories.add(DEFAULT_USER_AUTH_PUBLIC_KEY_FACTORY);
        }

        if (manager.getGSSAuthenticator() != null) {
            factories.add(DEFAULT_USER_AUTH_GSS_FACTORY);
        }

        return factories;
    }
}
