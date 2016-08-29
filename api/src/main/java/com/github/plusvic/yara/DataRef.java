package com.github.plusvic.yara;

/**
 * Created by styagi on 29/08/16.
 */
public class DataRef<T> {
    private final T data;

    public DataRef(T data) {
        this.data = data;
    }

    public T getReference() {
        return data;
    }
}
