package com.aevum.core.pipeline;

import com.aevum.core.domain.model.*;
import com.aevum.core.engine.*;
import java.nio.file.Path;
import java.util.*;

/**
 * Shared context across pipeline stages.
 */
public class StageContext {
    private final EffectivePom effectivePom;
    private final Path buildOutput;
    private final List<String> entryPoints;
    private final boolean networkExposed;
    private final Map<String, Object> sharedData;

    public StageContext(EffectivePom effectivePom, Path buildOutput,
                        List<String> entryPoints, boolean networkExposed) {
        this.effectivePom = effectivePom;
        this.buildOutput = buildOutput;
        this.entryPoints = List.copyOf(entryPoints);
        this.networkExposed = networkExposed;
        this.sharedData = new HashMap<>();
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
