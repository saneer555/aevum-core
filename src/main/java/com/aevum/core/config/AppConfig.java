package com.aevum.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.VirtualThreadTaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.concurrent.Executor;

/**
 * Application configuration for virtual threads and async processing.
 */
@Configuration
@EnableAsync
public class AppConfig {

    @Bean(name = "virtualThreadExecutor")
    public Executor virtualThreadExecutor() {
        return new VirtualThreadTaskExecutor("aevum-vt-");
    }
}
