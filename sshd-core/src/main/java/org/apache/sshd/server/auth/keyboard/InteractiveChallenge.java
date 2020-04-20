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

package org.apache.sshd.server.auth.keyboard;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;

/**
 * Represents a server &quot;challenge&quot; as per <A HREF="https://tools.ietf.org/html/rfc4256">RFC-4256</A>
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class InteractiveChallenge implements Cloneable {
    private String interactionName;
    private String interactionInstruction;
    private String languageTag;
    private List<PromptEntry> prompts = new ArrayList<>();

    public InteractiveChallenge() {
        super();
    }

    public String getInteractionName() {
        return interactionName;
    }

    public void setInteractionName(String interactionName) {
        this.interactionName = interactionName;
    }

    public String getInteractionInstruction() {
        return interactionInstruction;
    }

    public void setInteractionInstruction(String interactionInstruction) {
        this.interactionInstruction = interactionInstruction;
    }

    public String getLanguageTag() {
        return languageTag;
    }

    public void setLanguageTag(String languageTag) {
        this.languageTag = languageTag;
    }

    public void addPrompt(String prompt, boolean echo) {
        addPrompt(new PromptEntry(prompt, echo));
    }

    public void addPrompt(PromptEntry entry) {
        this.prompts.add(Objects.requireNonNull(entry, "No entry"));
    }

    public List<PromptEntry> getPrompts() {
        return prompts;
    }

    // NOTE: prompts are COPIED to the local one
    public void setPrompts(Collection<? extends PromptEntry> prompts) {
        clearPrompts();

        if (GenericUtils.size(prompts) > 0) {
            this.prompts.addAll(prompts);
        }
    }

    public void clearPrompts() {
        this.prompts.clear();
    }

    public <B extends Buffer> B append(B buffer) {
        buffer.putString(getInteractionName());
        buffer.putString(getInteractionInstruction());
        buffer.putString(getLanguageTag());

        List<PromptEntry> entries = getPrompts();
        int numEntries = GenericUtils.size(entries);
        buffer.putInt(numEntries);

        for (int index = 0; index < numEntries; index++) {
            PromptEntry e = entries.get(index);
            e.append(buffer);
        }

        return buffer;
    }

    @Override
    public InteractiveChallenge clone() {
        try {
            InteractiveChallenge other = getClass().cast(super.clone());
            other.prompts = new ArrayList<>();
            for (PromptEntry entry : getPrompts()) {
                other.addPrompt(entry.clone());
            }
            return other;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException("Failed to clone " + toString() + ": " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        return getInteractionName()
               + "[" + getInteractionInstruction() + "]"
               + "(" + getLanguageTag() + ")"
               + ": " + getPrompts();
    }
}
