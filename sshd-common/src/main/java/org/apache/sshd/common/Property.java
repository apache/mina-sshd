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
package org.apache.sshd.common;

import java.nio.charset.Charset;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Property definition.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Property<T> {

    static Property<String> string(String name) {
        return new StringProperty(name);
    }

    static Property<String> string(String name, String def) {
        return new StringProperty(name, def);
    }

    static Property<Boolean> bool(String name) {
        return new BooleanProperty(name);
    }

    static Property<Boolean> bool(String name, boolean def) {
        return new BooleanProperty(name, def);
    }

    static Property<Integer> integer(String name) {
        return new IntProperty(name);
    }

    static Property<Integer> integer(String name, int def) {
        return new IntProperty(name, def);
    }

    // CHECKSTYLE:OFF
    static Property<Long> long_(String name) {
        return new LongProperty(name);
    }

    static Property<Long> long_(String name, long def) {
        return new LongProperty(name, def);
    }

    static <T extends Enum<T>> Property<T> enum_(String name, Class<T> type) {
        return new EnumProperty<>(name, type);
    }

    static <T extends Enum<T>> Property<T> enum_(String name, Class<T> type, T def) {
        return new EnumProperty<>(name, type, def);
    }
    // CHECKSTYLE:ON

    static Property<Duration> duration(String name) {
        return new DurationProperty(name);
    }

    static Property<Duration> duration(String name, Duration def) {
        return new DurationProperty(name, def);
    }

    static Property<Duration> durationSec(String name) {
        return new DurationInSecondsProperty(name);
    }

    static Property<Duration> durationSec(String name, Duration def) {
        return new DurationInSecondsProperty(name, def);
    }

    static Property<Charset> charset(String name) {
        return new CharsetProperty(name);
    }

    static Property<Charset> charset(String name, Charset def) {
        return new CharsetProperty(name, def);
    }

    static Property<Object> object(String name) {
        return new ObjectProperty(name);
    }

    static Property<Object> object(String name, Object def) {
        return new ObjectProperty(name, def);
    }

    static <T> Property<T> validating(Property<T> prop, Consumer<T> validator) {
        return new Validating<>(prop, validator);
    }

    abstract class BaseProperty<T> implements Property<T> {

        private final String name;
        private final T defaultValue;

        public BaseProperty(String name) {
            this(name, null);
        }

        public BaseProperty(String name, T defaultValue) {
            this.name = Objects.requireNonNull(name, "No name provided");
            this.defaultValue = defaultValue;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Optional<T> getDefault() {
            return Optional.ofNullable(defaultValue);
        }

        @Override
        public T getRequiredDefault() {
            return getDefault().get();
        }

        @Override
        public Optional<T> get(PropertyResolver resolver) {
            Object propValue = PropertyResolverUtils.resolvePropertyValue(resolver, name);
            return propValue != null ? Optional.of(fromStorage(propValue)) : getDefault();
        }

        @Override
        public T getRequired(PropertyResolver resolver) {
            return get(resolver).get();
        }

        @Override
        public T getOrNull(PropertyResolver resolver) {
            return get(resolver).orElse(null);
        }

        @Override
        public void set(PropertyResolver resolver, T value) {
            PropertyResolverUtils.updateProperty(resolver, name, toStorage(value));
        }

        @Override
        public void remove(PropertyResolver resolver) {
            PropertyResolverUtils.updateProperty(resolver, name, null);
        }

        protected Object toStorage(T value) {
            return value;
        }

        protected abstract T fromStorage(Object value);

        @Override
        public String toString() {
            return "Property[" + name + "]";
        }
    }

    class DurationProperty extends BaseProperty<Duration> {

        public DurationProperty(String name) {
            super(name);
        }

        public DurationProperty(String name, Duration def) {
            super(name, def);
        }

        @Override
        protected Object toStorage(Duration value) {
            return value != null ? value.toMillis() : null;
        }

        @Override
        protected Duration fromStorage(Object value) {
            Long val = PropertyResolverUtils.toLong(value);
            return val != null ? Duration.ofMillis(val) : null;
        }
    }

    class DurationInSecondsProperty extends DurationProperty {
        public DurationInSecondsProperty(String name) {
            super(name);
        }

        public DurationInSecondsProperty(String name, Duration def) {
            super(name, def);
        }

        @Override
        protected Object toStorage(Duration value) {
            return value != null ? value.toMillis() / 1_000 : null;
        }

        @Override
        protected Duration fromStorage(Object value) {
            Long val = PropertyResolverUtils.toLong(value);
            return val != null ? Duration.ofSeconds(val) : null;
        }
    }

    class StringProperty extends BaseProperty<String> {

        public StringProperty(String name) {
            super(name);
        }

        public StringProperty(String name, String def) {
            super(name, def);
        }

        @Override
        protected String fromStorage(Object value) {
            return value != null ? value.toString() : null;
        }
    }

    class BooleanProperty extends BaseProperty<Boolean> {

        public BooleanProperty(String name) {
            super(name);
        }

        public BooleanProperty(String name, Boolean defaultValue) {
            super(name, defaultValue);
        }

        @Override
        protected Boolean fromStorage(Object value) {
            return PropertyResolverUtils.toBoolean(value);
        }

    }

    class LongProperty extends BaseProperty<Long> {

        public LongProperty(String name) {
            super(name);
        }

        public LongProperty(String name, Long defaultValue) {
            super(name, defaultValue);
        }

        @Override
        protected Long fromStorage(Object value) {
            return PropertyResolverUtils.toLong(value);
        }
    }

    class IntProperty extends BaseProperty<Integer> {

        public IntProperty(String name) {
            super(name);
        }

        public IntProperty(String name, Integer defaultValue) {
            super(name, defaultValue);
        }

        @Override
        protected Integer fromStorage(Object value) {
            return PropertyResolverUtils.toInteger(value);
        }
    }

    class CharsetProperty extends BaseProperty<Charset> {

        public CharsetProperty(String name) {
            super(name);
        }

        public CharsetProperty(String name, Charset defaultValue) {
            super(name, defaultValue);
        }

        @Override
        protected Charset fromStorage(Object value) {
            return PropertyResolverUtils.toCharset(value);
        }
    }

    class ObjectProperty extends BaseProperty<Object> {

        public ObjectProperty(String name) {
            super(name);
        }

        public ObjectProperty(String name, Object defaultValue) {
            super(name, defaultValue);
        }

        @Override
        protected Object fromStorage(Object value) {
            return value;
        }
    }

    class EnumProperty<T extends Enum<T>> extends BaseProperty<T> {

        private final Class<T> type;

        public EnumProperty(String name, Class<T> type) {
            super(name);
            this.type = Objects.requireNonNull(type, "type is required");
        }

        public EnumProperty(String name, Class<T> type, T def) {
            super(name, def);
            this.type = Objects.requireNonNull(type, "type is required");
        }

        @Override
        protected T fromStorage(Object value) {
            return PropertyResolverUtils.toEnum(type, value, false, Arrays.asList(type.getEnumConstants()));
        }
    }

    class Validating<T> implements Property<T> {
        private final Property<T> delegate;
        private final Consumer<T> validator;

        public Validating(Property<T> delegate, Consumer<T> validator) {
            this.delegate = delegate;
            this.validator = validator;
        }

        @Override
        public String getName() {
            return delegate.getName();
        }

        @Override
        public Optional<T> getDefault() {
            return delegate.getDefault();
        }

        @Override
        public T getRequiredDefault() {
            return delegate.getRequiredDefault();
        }

        @Override
        public Optional<T> get(PropertyResolver resolver) {
            Optional<T> t = delegate.get(resolver);
            t.ifPresent(validator);
            return t;
        }

        @Override
        public T getRequired(PropertyResolver resolver) {
            return get(resolver).get();
        }

        @Override
        public T getOrNull(PropertyResolver resolver) {
            return get(resolver).orElse(null);
        }

        @Override
        public void set(PropertyResolver resolver, T value) {
            validator.accept(value);
            delegate.set(resolver, value);
        }

        @Override
        public void remove(PropertyResolver resolver) {
            delegate.remove(resolver);
        }
    }

    String getName();

    Optional<T> getDefault();

    T getRequiredDefault();

    Optional<T> get(PropertyResolver resolver);

    T getRequired(PropertyResolver resolver);

    T getOrNull(PropertyResolver resolver);

    void set(PropertyResolver resolver, T value);

    void remove(PropertyResolver resolver);
}
