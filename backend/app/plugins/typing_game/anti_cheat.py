# backend/app/plugins/typing_game/anti_cheat.py
"""
Anti-Cheat Validation Module for Typing Game

Analyzes typing behavior data to detect cheating:
- Impossibly fast typing speeds
- Unnaturally consistent timing (bot-like behavior)
- Speed spikes and instant starts
- Copy-paste attempts
- Focus loss during gameplay

Returns a confidence score (0-1) where:
- 1.0 = Highly confident legitimate
- 0.6+ = Acceptable
- 0.3-0.6 = Flag for review
- <0.3 = Reject
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import math
import statistics


class AntiCheatFlag(str, Enum):
    """Types of suspicious activity detected"""
    IMPOSSIBLE_SPEED = "impossible_speed"
    TOO_CONSISTENT = "too_consistent_timing"
    SPEED_SPIKE = "suspicious_speed_spike"
    INSTANT_START = "instant_high_speed_start"
    PASTE_DETECTED = "paste_attempted"
    EXCESSIVE_FOCUS_LOSS = "excessive_focus_loss"
    SPEED_VARIATION_LOW = "unnaturally_low_speed_variation"
    WPM_TOO_HIGH = "wpm_exceeds_human_limit"


@dataclass
class AntiCheatThresholds:
    """Configurable thresholds for anti-cheat detection"""
    # Timing thresholds (milliseconds)
    MIN_INTER_KEY_TIME: float = 15.0  # True physical limit (key rollover can produce 20-30ms)
    KEY_BOUNCE_THRESHOLD: float = 10.0  # Below this is keyboard bounce/artifact, filter out
    IMPOSSIBLE_SPEED_RATIO: float = 0.10  # Flag if >10% of keystrokes are below MIN_INTER_KEY_TIME
    MAX_REASONABLE_WPM: int = 250  # World record is ~216 WPM

    # Consistency thresholds
    MIN_STD_DEV_RATIO: float = 0.15  # Too consistent = bot (std_dev / avg)
    MIN_COEFFICIENT_VARIATION: float = 0.20  # Another consistency check

    # Speed ramp-up thresholds
    MAX_SPEED_SPIKE_RATIO: float = 3.0  # Can't triple speed suddenly
    MAX_INSTANT_START_WPM: int = 130  # Can't start at 130+ WPM instantly
    MIN_RAMP_UP_FACTOR: float = 0.5  # First segment should be slower

    # Focus/activity thresholds
    MAX_FOCUS_LOST_COUNT: int = 3  # Warn at 3, flag at 5
    MAX_TOTAL_FOCUS_LOST_MS: int = 10000  # 10 seconds total away

    # Scoring thresholds
    SUSPICIOUS_THRESHOLD: float = 0.6  # Flag for review if below this
    REJECT_THRESHOLD: float = 0.3  # Auto-reject if below this


@dataclass
class AntiCheatResult:
    """Result of anti-cheat validation"""
    is_valid: bool
    confidence_score: float  # 0.0 - 1.0
    flags: List[str]
    should_flag_for_review: bool
    adjusted_xp_multiplier: float  # 1.0 for legitimate, reduced for suspicious
    details: Dict[str, any]


class AntiCheatValidator:
    """Validates typing game sessions for suspicious activity"""

    def __init__(self, thresholds: Optional[AntiCheatThresholds] = None):
        self.thresholds = thresholds or AntiCheatThresholds()

    def validate(
        self,
        keystroke_timings: List[float],
        keystroke_count: int,
        paste_attempts: int,
        focus_lost_count: int,
        total_focus_lost_time: float,
        wpm: float,
        accuracy: float,
        time_elapsed: float,
        first_segment_avg: Optional[float] = None,
        last_segment_avg: Optional[float] = None,
    ) -> AntiCheatResult:
        """
        Validate a typing session for suspicious activity.

        Args:
            keystroke_timings: List of inter-key intervals in milliseconds
            keystroke_count: Total number of keystrokes
            paste_attempts: Number of paste attempts detected
            focus_lost_count: Number of times focus was lost
            total_focus_lost_time: Total time (ms) focus was away
            wpm: Final words per minute
            accuracy: Final accuracy percentage
            time_elapsed: Total time in seconds
            first_segment_avg: Average inter-key time for first 10 keystrokes
            last_segment_avg: Average inter-key time for last 10 keystrokes

        Returns:
            AntiCheatResult with validation outcome
        """
        confidence = 1.0
        flags: List[str] = []
        details: Dict[str, any] = {}

        # Calculate statistics if we have timing data
        if len(keystroke_timings) >= 10:
            # Filter out keyboard bounce artifacts (< 10ms) before analysis
            filtered_timings = [
                t for t in keystroke_timings
                if t >= self.thresholds.KEY_BOUNCE_THRESHOLD
            ]
            bounced_count = len(keystroke_timings) - len(filtered_timings)

            # Use filtered timings for stats, fall back to raw if all filtered
            analysis_timings = filtered_timings if len(filtered_timings) >= 5 else keystroke_timings

            avg_time = statistics.mean(analysis_timings)
            std_dev = statistics.stdev(analysis_timings) if len(analysis_timings) > 1 else 0
            min_time = min(analysis_timings)
            max_time = max(analysis_timings)

            details["avg_inter_key_time"] = round(avg_time, 2)
            details["std_dev_inter_key_time"] = round(std_dev, 2)
            details["min_inter_key_time"] = round(min_time, 2)
            details["max_inter_key_time"] = round(max_time, 2)
            if bounced_count > 0:
                details["key_bounce_filtered"] = bounced_count

            # 1. Check for impossible speed (proportion-based)
            # Only flag if a significant percentage of keystrokes are impossibly fast
            impossible_count = sum(
                1 for t in filtered_timings
                if t < self.thresholds.MIN_INTER_KEY_TIME
            )
            impossible_ratio = impossible_count / len(filtered_timings) if filtered_timings else 0

            if impossible_ratio > self.thresholds.IMPOSSIBLE_SPEED_RATIO:
                # Scale penalty based on how many keystrokes are suspicious
                penalty = min(0.4, impossible_ratio * 2.0)  # Max 0.4
                confidence -= penalty
                flags.append(AntiCheatFlag.IMPOSSIBLE_SPEED.value)
                details["impossible_speed_detected"] = True
                details["impossible_speed_count"] = impossible_count
                details["impossible_speed_ratio"] = round(impossible_ratio, 3)
                details["fastest_keystroke_ms"] = round(min_time, 2)
            elif impossible_count > 0:
                # A few fast keystrokes is normal (key rollover) - just note it
                details["fast_keystrokes_count"] = impossible_count
                details["fastest_keystroke_ms"] = round(min_time, 2)

            # 2. Check for too-consistent timing (bot behavior)
            if avg_time > 0:
                std_ratio = std_dev / avg_time
                coef_variation = std_dev / avg_time

                if std_ratio < self.thresholds.MIN_STD_DEV_RATIO:
                    confidence -= 0.3
                    flags.append(AntiCheatFlag.TOO_CONSISTENT.value)
                    details["std_ratio"] = round(std_ratio, 3)

                if coef_variation < self.thresholds.MIN_COEFFICIENT_VARIATION:
                    confidence -= 0.15
                    flags.append(AntiCheatFlag.SPEED_VARIATION_LOW.value)
                    details["coefficient_variation"] = round(coef_variation, 3)

            # 3. Check for speed spike (sudden increase)
            if first_segment_avg and last_segment_avg and first_segment_avg > 0:
                # Lower time = faster typing
                speed_ratio = first_segment_avg / last_segment_avg
                if speed_ratio > self.thresholds.MAX_SPEED_SPIKE_RATIO:
                    confidence -= 0.2
                    flags.append(AntiCheatFlag.SPEED_SPIKE.value)
                    details["speed_spike_ratio"] = round(speed_ratio, 2)

            # 4. Check for instant start at high speed
            if first_segment_avg and first_segment_avg > 0:
                # Convert inter-key time to WPM (rough approximation)
                # chars per minute = (1000 / avg_ms) * 60
                # WPM = chars per minute / 5
                first_wpm = (1000 / first_segment_avg) * 60 / 5
                if first_wpm > self.thresholds.MAX_INSTANT_START_WPM:
                    confidence -= 0.25
                    flags.append(AntiCheatFlag.INSTANT_START.value)
                    details["first_segment_wpm"] = round(first_wpm, 1)

        # 5. Check paste attempts
        if paste_attempts > 0:
            confidence -= 0.5  # Major red flag
            flags.append(AntiCheatFlag.PASTE_DETECTED.value)
            details["paste_attempts"] = paste_attempts

        # 6. Check focus loss
        if focus_lost_count > self.thresholds.MAX_FOCUS_LOST_COUNT:
            penalty = 0.1 * (focus_lost_count - self.thresholds.MAX_FOCUS_LOST_COUNT)
            confidence -= min(penalty, 0.3)  # Cap at 0.3
            flags.append(AntiCheatFlag.EXCESSIVE_FOCUS_LOSS.value)
            details["focus_lost_count"] = focus_lost_count

        if total_focus_lost_time > self.thresholds.MAX_TOTAL_FOCUS_LOST_MS:
            confidence -= 0.1
            details["total_focus_lost_ms"] = total_focus_lost_time

        # 7. Check WPM against human limits
        if wpm > self.thresholds.MAX_REASONABLE_WPM:
            confidence -= 0.5
            flags.append(AntiCheatFlag.WPM_TOO_HIGH.value)
            details["reported_wpm"] = wpm

        # Clamp confidence to valid range
        confidence = max(0.0, min(1.0, confidence))

        # Determine validity and review status
        is_valid = confidence >= self.thresholds.REJECT_THRESHOLD
        should_review = (
            confidence < self.thresholds.SUSPICIOUS_THRESHOLD and
            confidence >= self.thresholds.REJECT_THRESHOLD
        )

        # Calculate XP multiplier (penalize suspicious activity)
        if confidence >= self.thresholds.SUSPICIOUS_THRESHOLD:
            xp_multiplier = 1.0
        elif confidence >= self.thresholds.REJECT_THRESHOLD:
            # Gradual penalty between reject and suspicious thresholds
            xp_multiplier = 0.5 + (confidence - self.thresholds.REJECT_THRESHOLD) / 0.6
        else:
            xp_multiplier = 0.0  # No XP for rejected sessions

        return AntiCheatResult(
            is_valid=is_valid,
            confidence_score=round(confidence, 3),
            flags=flags,
            should_flag_for_review=should_review,
            adjusted_xp_multiplier=round(xp_multiplier, 2),
            details=details,
        )


# Singleton instance
_validator: Optional[AntiCheatValidator] = None


def get_validator() -> AntiCheatValidator:
    """Get or create the anti-cheat validator instance"""
    global _validator
    if _validator is None:
        _validator = AntiCheatValidator()
    return _validator


def validate_typing_session(
    keystroke_timings: List[float],
    keystroke_count: int,
    paste_attempts: int = 0,
    focus_lost_count: int = 0,
    total_focus_lost_time: float = 0,
    wpm: float = 0,
    accuracy: float = 0,
    time_elapsed: float = 0,
    first_segment_avg: Optional[float] = None,
    last_segment_avg: Optional[float] = None,
) -> AntiCheatResult:
    """
    Convenience function to validate a typing session.

    Returns AntiCheatResult with validation outcome.
    """
    validator = get_validator()
    return validator.validate(
        keystroke_timings=keystroke_timings,
        keystroke_count=keystroke_count,
        paste_attempts=paste_attempts,
        focus_lost_count=focus_lost_count,
        total_focus_lost_time=total_focus_lost_time,
        wpm=wpm,
        accuracy=accuracy,
        time_elapsed=time_elapsed,
        first_segment_avg=first_segment_avg,
        last_segment_avg=last_segment_avg,
    )
