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

package org.apache.sshd.common.kex;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public enum KexProposalOption {
    ALGORITHMS(Constants.PROPOSAL_KEX_ALGS, "kex algorithms"),
    SERVERKEYS(Constants.PROPOSAL_SERVER_HOST_KEY_ALGS, "server host key algorithms"),
    C2SENC(Constants.PROPOSAL_ENC_ALGS_CTOS, "encryption algorithms (client to server)"),
    S2CENC(Constants.PROPOSAL_ENC_ALGS_STOC, "encryption algorithms (server to client)"),
    C2SMAC(Constants.PROPOSAL_MAC_ALGS_CTOS, "mac algorithms (client to server)"),
    S2CMAC(Constants.PROPOSAL_MAC_ALGS_STOC, "mac algorithms (server to client)"),
    C2SCOMP(Constants.PROPOSAL_COMP_ALGS_CTOS, "compression algorithms (client to server)"),
    S2CCOMP(Constants.PROPOSAL_COMP_ALGS_STOC, "compression algorithms (server to client)"),
    C2SLANG(Constants.PROPOSAL_LANG_CTOS, "languages (client to server)"),
    S2CLANG(Constants.PROPOSAL_LANG_STOC, "languages (server to client)");

    /**
     * A {@link List} of all the options <U>sorted</U> according to {@link #getProposalIndex()}
     *
     * @see #BY_PROPOSAL_INDEX
     */
    public static final List<KexProposalOption> VALUES =
        Collections.unmodifiableList(new ArrayList<KexProposalOption>(EnumSet.allOf(KexProposalOption.class)) {
            private static final long serialVersionUID = 1L;    // we're not serializing it

            {
                Collections.sort(this, BY_PROPOSAL_INDEX);
            }
        });

    public static final int PROPOSAL_MAX = VALUES.size();

    /**
     * Compares values according to {@link KexProposalOption#getProposalIndex()}
     */
    public static final Comparator<KexProposalOption> BY_PROPOSAL_INDEX =
        new Comparator<KexProposalOption>() {
            @Override
            public int compare(KexProposalOption o1, KexProposalOption o2) {
                int i1 = (o1 == null) ? -1 : o1.getProposalIndex();
                int i2 = (o2 == null) ? -1 : o2.getProposalIndex();
                return Integer.compare(i1, i2);
            }
        };

    private final int proposalIndex;

    private final String description;

    KexProposalOption(int index, String desc) {
        proposalIndex = index;
        description = desc;
    }

    /**
     * @return The proposal option location in the KEX array
     */
    public final int getProposalIndex() {
        return proposalIndex;
    }

    /**
     * @return User-friendly name for the KEX negotiation item
     * @see <A HREF="http://tools.ietf.org/html/rfc4253#section-7.1">RFC-4253 - section 7.1</A>
     */
    public final String getDescription() {
        return description;
    }

    /**
     * @param n The option name - ignored if {@code null}/empty
     * @return The matching {@link KexProposalOption#name()} - case <U>insensitive</U>
     * or {@code null} if no match found
     */
    public static KexProposalOption fromName(String n) {
        if (GenericUtils.isEmpty(n)) {
            return null;
        }

        for (KexProposalOption o : VALUES) {
            if (n.equalsIgnoreCase(o.name())) {
                return o;
            }
        }

        return null;
    }

    public static KexProposalOption fromProposalIndex(int index) {
        if ((index < 0) || (index >= VALUES.size())) {
            return null;
        } else {
            return VALUES.get(index);
        }
    }

    public static final class Constants {
        public static final int PROPOSAL_KEX_ALGS = 0;
        public static final int PROPOSAL_SERVER_HOST_KEY_ALGS = 1;
        public static final int PROPOSAL_ENC_ALGS_CTOS = 2;
        public static final int PROPOSAL_ENC_ALGS_STOC = 3;
        public static final int PROPOSAL_MAC_ALGS_CTOS = 4;
        public static final int PROPOSAL_MAC_ALGS_STOC = 5;
        public static final int PROPOSAL_COMP_ALGS_CTOS = 6;
        public static final int PROPOSAL_COMP_ALGS_STOC = 7;
        public static final int PROPOSAL_LANG_CTOS = 8;
        public static final int PROPOSAL_LANG_STOC = 9;
    }
}
