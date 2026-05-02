package com.aevum.core.domain.enums;

/**
 * Types of fixes that can be applied.
 *
 * NOTE: NO_FIX_REQUIRED is included for completeness but FixEngine never generates
 * a FixOption with this type. FixRankingService.getFixTypePriority() must handle it
 * (returns lowest priority = highest number).
 */
public enum FixType {
    VERSION_ALIGNMENT,
    DEPENDENCY_EXCLUSION,
    PARENT_UPGRADE,
    NO_FIX_REQUIRED
}