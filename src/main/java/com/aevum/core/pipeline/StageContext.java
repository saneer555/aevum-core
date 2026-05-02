package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared context across pipeline stages.
 *
 * FIX: Changed sharedData from HashMap to ConcurrentHashMap.
 * Stages 3-5 run in parallel virtual threads and all call context.put() concurrently.
 * HashMap is NOT thread-safe — ConcurrentHashMap is required here.
 */
public class StageContext {
    private final EffectivePom effectivePom;
    private final Path buildOutput;
    private final List<String> entryPoints;
    private final boolean networkExposed;
    private final ConcurrentHashMap<String, Object> sharedData;

    public StageContext(EffectivePom effectivePom, Path buildOutput,
                        List<String> entryPoints, boolean networkExposed) {
        this.effectivePom = effectivePom;
        this.buildOutput = buildOutput;
        this.entryPoints = List.copyOf(entryPoints != null ? entryPoints : List.of());
        this.networkExposed = networkExposed;
        this.sharedData = new ConcurrentHashMap<>();
    }

    public EffectivePom getEffectivePom() { return effectivePom; }
    public Path getBuildOutput() { return buildOutput; }
    public List<String> getEntryPoints() { return entryPoints; }
    public boolean isNetworkExposed() { return networkExposed; }

    @SuppressWarnings("unchecked")
    public <T> Optional<T> get(String key) {
        return Optional.ofNullable((T) sharedData.get(key));
    }

    public void put(String key, Object value) {
        sharedData.put(key, value);
    }
}