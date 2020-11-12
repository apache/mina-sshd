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
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import org.apache.sshd.common.util.ValidateUtils;

/**
 * Property definition.
 *
 * @param  <T> The generic property type
 * @author     <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Property<T> extends NamedResource {

    static Property<String> string(String name) {
        return string(name, null);
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
        return new IntegerProperty(name);
    }

    static Property<Integer> integer(String name, int def) {
        return new IntegerProperty(name, def);
    }

    // CHECKSTYLE:OFF
    static Property<Long> long_(String name) {
        return new LongProperty(name);
    }

    static Property<Long> long_(String name, long def) {
        return new LongProperty(name, def);
    }

    static <T extends Enum<T>> Property<T> enum_(String name, Class<T> type) {
        return enum_(name, type, null);
    }

    static <T extends Enum<T>> Property<T> enum_(String name, Class<T> type, T def) {
        return new EnumProperty<>(name, type, def);
    }
    // CHECKSTYLE:ON

    static Property<Duration> duration(String name) {
        return duration(name, null);
    }

    static Property<Duration> duration(String name, Duration def) {
        return new DurationProperty(name, def);
    }

    static Property<Duration> durationSec(String name) {
        return durationSec(name, null);
    }

    static Property<Duration> durationSec(String name, Duration def) {
        return new DurationInSecondsProperty(name, def);
    }

    static Property<Charset> charset(String name) {
        return charset(name, null);
    }

    static Property<Charset> charset(String name, Charset def) {
        return new CharsetProperty(name, def);
    }

    static Property<Object> object(String name) {
        return object(name, null);
    }

    static Property<Object> object(String name, Object def) {
        return new ObjectProperty(name, def);
    }

    static <T> Property<T> validating(Property<T> prop, Consumer<? super T> validator) {
        return new Validating<>(prop, validator);
    }

    abstract class BaseProperty<T> implements Property<T> {
        private final String name;
        private final Class<T> type;
        private final Optional<T> defaultValue;

        protected BaseProperty(String name, Class<T> type) {
            this(name, type, null);
        }

        protected BaseProperty(String name, Class<T> type, T defaultValue) {
            this.name = ValidateUtils.checkNotNullAndNotEmpty(name, "No name provided");
            this.type = Objects.requireNonNull(type, "Type must be provided");
            this.defaultValue = Optional.ofNullable(defaultValue);
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Class<T> getType() {
            return type;
        }

        @Override
        public Optional<T> getDefault() {
            return defaultValue;
        }

        @Override
        public Optional<T> get(PropertyResolver resolver) {
            Object propValue = PropertyResolverUtils.resolvePropertyValue(resolver, getName());
            return (propValue != null) ? Optional.of(fromStorage(propValue)) : getDefault();
        }

        @Override
        public T getOrCustomDefault(PropertyResolver resolver, T defaultValue) {
            Object propValue = PropertyResolverUtils.resolvePropertyValue(resolver, getName());
            return (propValue != null) ? fromStorage(propValue) : defaultValue;
        }

        @Override
        public void set(PropertyResolver resolver, T value) {
            PropertyResolverUtils.updateProperty(resolver, getName(), toStorage(value));
        }

        protected Object toStorage(T value) {
            return value;
        }

        protected abstract T fromStorage(Object value);

        @Override
        public String toString() {
            return "Property[" + getName() + "](" + getType().getSimpleName() + "]";
        }
    }

    class DurationProperty extends BaseProperty<Duration> {
        public DurationProperty(String name) {
            this(name, null);
        }

        public DurationProperty(String name, Duration def) {
            super(name, Duration.class, def);
        }

        @Override
        protected Object toStorage(Duration value) {
            return (value != null) ? value.toMillis() : null;
        }

        @Override
        protected Duration fromStorage(Object value) {
            Long val = PropertyResolverUtils.toLong(value);
            return (val != null) ? Duration.ofMillis(val) : null;
        }
    }

    class DurationInSecondsProperty extends DurationProperty {
        public DurationInSecondsProperty(String name) {
            this(name, null);
        }

        public DurationInSecondsProperty(String name, Duration def) {
            super(name, def);
        }

        @Override
        protected Object toStorage(Duration value) {
            return (value != null) ? (value.toMillis() / 1_000L) : null;
        }

        @Override
        protected Duration fromStorage(Object value) {
            Long val = PropertyResolverUtils.toLong(value);
            return val != null ? Duration.ofSeconds(val) : null;
        }
    }

    class StringProperty extends BaseProperty<String> {
        public StringProperty(String name) {
            this(name, null);
        }

        public StringProperty(String name, String def) {
            super(name, String.class, def);
        }

        @Override
        protected String fromStorage(Object value) {
            return (value != null) ? value.toString() : null;
        }
    }

    class BooleanProperty extends BaseProperty<Boolean> {
        public BooleanProperty(String name) {
            this(name, null);
        }

        public BooleanProperty(String name, Boolean defaultValue) {
            super(name, Boolean.class, defaultValue);
        }

        @Override
        protected Boolean fromStorage(Object value) {
            return PropertyResolverUtils.toBoolean(value);
        }
    }

    class LongProperty extends BaseProperty<Long> {
        public LongProperty(String name) {
            this(name, null);
        }

        public LongProperty(String name, Long defaultValue) {
            super(name, Long.class, defaultValue);
        }

        @Override
        protected Long fromStorage(Object value) {
            return PropertyResolverUtils.toLong(value);
        }
    }

    class IntegerProperty extends BaseProperty<Integer> {
        public IntegerProperty(String name) {
            this(name, null);
        }

        public IntegerProperty(String name, Integer defaultValue) {
            super(name, Integer.class, defaultValue);
        }

        @Override
        protected Integer fromStorage(Object value) {
            return PropertyResolverUtils.toInteger(value);
        }
    }

    class CharsetProperty extends BaseProperty<Charset> {
        public CharsetProperty(String name) {
            this(name, null);
        }

        public CharsetProperty(String name, Charset defaultValue) {
            super(name, Charset.class, defaultValue);
        }

        @Override
        protected Charset fromStorage(Object value) {
            return PropertyResolverUtils.toCharset(value);
        }
    }

    class ObjectProperty extends BaseProperty<Object> {
        public ObjectProperty(String name) {
            this(name, null);
        }

        public ObjectProperty(String name, Object defaultValue) {
            super(name, Object.class, defaultValue);
        }

        @Override
        protected Object fromStorage(Object value) {
            return value;
        }
    }

    class EnumProperty<T extends Enum<T>> extends BaseProperty<T> {
        protected final Collection<T> values;

        public EnumProperty(String name, Class<T> type) {
            this(name, type, null);
        }

        public EnumProperty(String name, Class<T> type, T def) {
            super(name, type, def);
            values = Collections.unmodifiableSet(EnumSet.allOf(type));
        }

        @Override
        protected T fromStorage(Object value) {
            Class<T> type = getType();
            return PropertyResolverUtils.toEnum(type, value, false, values);
        }
    }

    class Validating<T> implements Property<T> {
        protected final Property<T> delegate;
        protected final Consumer<? super T> validator;

        public Validating(Property<T> delegate, Consumer<? super T> validator) {
            this.delegate = delegate;
            this.validator = validator;
        }

        @Override
        public String getName() {
            return delegate.getName();
        }

        @Override
        public Class<T> getType() {
            return delegate.getType();
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
        public T getOrCustomDefault(PropertyResolver resolver, T defaultValue) {
            T value = delegate.getOrCustomDefault(resolver, defaultValue);
            validator.accept(value);
            return value;
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

    /**
     * @return Property type - <B>Note:</B> for primitive types the wrapper equivalent is returned
     */
    Class<T> getType();

    /**
     * @return The {@link Optional} pre-defined default value
     */
    Optional<T> getDefault();

    default T getRequiredDefault() {
        return getDefault().get();
    }

    /**
     * @param  resolver The {@link PropertyResolver} to query for the property value.
     * @return          The {@link Optional} result - if resolver contains a value then the resolver's value, otherwise
     *                  the pre-defined {@link #getDefault() default}
     */
    Optional<T> get(PropertyResolver resolver);

    /**
     * @param  resolver               The {@link PropertyResolver} to query for the property value.
     * @return                        The resolved value
     * @throws NoSuchElementException if resolver contains no value and no {@link #getDefault()} defined
     */
    default T getRequired(PropertyResolver resolver) {
        return get(resolver).get();
    }

    /**
     * @param  resolver The {@link PropertyResolver} to query for the property value.
     * @return          The resolver's value or {@code null} if no specific value found in the resolver - regardless of
     *                  whether there is a default value
     */
    default T getOrNull(PropertyResolver resolver) {
        return getOrCustomDefault(resolver, null);
    }

    /**
     * @param  resolver     The {@link PropertyResolver} to query for the property value.
     * @param  defaultValue The default value to return if no specific value found in resolver
     * @return              The resolver's value or specified default if no specific value found in the resolver -
     *                      regardless of whether there is a default value
     */
    T getOrCustomDefault(PropertyResolver resolver, T defaultValue);

    /**
     * @param resolver The {@link PropertyResolver} to update with the property value.
     * @param value    The value to set
     */
    void set(PropertyResolver resolver, T value);

    /**
     * @param resolver The {@link PropertyResolver} to remove the property from
     */
    default void remove(PropertyResolver resolver) {
        PropertyResolverUtils.updateProperty(resolver, getName(), null);
    }
}
