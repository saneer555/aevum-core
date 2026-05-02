package com.aevum.core.util;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Compatibility shim to provide a virtual-thread-per-task executor when running on Java 21+.
 * Falls back to a cached thread pool on older JDKs to keep tests working.
 */
public final class Threading {
    private Threading() {}

    public static ExecutorService newVirtualThreadPerTaskExecutor() {
        try {
            // Use reflection to call Executors.newVirtualThreadPerTaskExecutor() on JDK 21+
            var method = Executors.class.getMethod("newVirtualThreadPerTaskExecutor");
            return (ExecutorService) method.invoke(null);
        } catch (ReflectiveOperationException e) {
            // Fallback: use cached thread pool (daemon threads would be ideal, but keep simple)
            return Executors.newCachedThreadPool();
        }
    }
}

