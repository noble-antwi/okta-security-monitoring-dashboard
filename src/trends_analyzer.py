"""
Trends analysis module for historical Okta authentication analytics.

Analyzes timestamped analysis files to calculate trends over time,
including 7-day/30-day trends and week-over-week comparisons.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple

logger = logging.getLogger(__name__)


class TrendsAnalyzer:
    """Analyze trends from timestamped analysis results."""

    def __init__(self, data_dir: str = "."):
        """
        Initialize trends analyzer.
        
        Args:
            data_dir: Directory containing analysis_results_*.json files
        """
        self.data_dir = Path(data_dir)
        self.analysis_files = self._get_analysis_files()

    def _get_analysis_files(self) -> List[Tuple[datetime, Path]]:
        """
        Get all timestamped analysis files sorted by timestamp.
        
        Returns:
            List of (timestamp, path) tuples sorted by timestamp
        """
        files = []
        pattern = "analysis_results_*.json"
        
        for file_path in self.data_dir.glob(pattern):
            try:
                # Extract timestamp from filename: analysis_results_YYYYMMDD_HHMMSS.json
                stem = file_path.stem  # Remove .json
                timestamp_str = stem.replace("analysis_results_", "")
                
                # Parse timestamp
                dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                files.append((dt, file_path))
            except (ValueError, IndexError) as e:
                logger.warning(f"Could not parse timestamp from {file_path.name}: {e}")
                continue
        
        # Sort by timestamp
        files.sort(key=lambda x: x[0])
        return files

    def _load_analysis(self, file_path: Path) -> Dict[str, Any] | None:
        """
        Load a single analysis file.
        
        Args:
            file_path: Path to analysis JSON file
            
        Returns:
            Analysis data or None if file cannot be loaded
        """
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading {file_path.name}: {e}")
            return None

    def _is_within_hours(self, timestamp: datetime, hours: int) -> bool:
        """
        Check if timestamp is within the specified hours from now.
        
        Args:
            timestamp: Datetime to check
            hours: Number of hours back from now
            
        Returns:
            True if timestamp is within hours, False otherwise
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        return timestamp >= cutoff

    def get_trend_data(self, hours: int = 168) -> Dict[str, Any]:
        """
        Get trend data for the last N hours.
        
        Args:
            hours: Number of hours to include (default 168 = 7 days)
            
        Returns:
            Dictionary with time-series trend data
        """
        # Filter files within the time range
        relevant_files = [
            (ts, path) for ts, path in self.analysis_files
            if self._is_within_hours(ts, hours)
        ]
        
        if not relevant_files:
            logger.warning(f"No analysis files found within last {hours} hours")
            return {
                "trend_type": f"last_{hours}h",
                "data_points": [],
                "summary": {
                    "total_events": [],
                    "failed_logins": [],
                    "successful_logins": [],
                    "unique_users": [],
                    "login_success_rate": []
                }
            }
        
        # Extract metrics from each file
        timestamps = []
        total_events = []
        failed_logins = []
        successful_logins = []
        unique_users = []
        login_success_rates = []
        
        for timestamp, file_path in relevant_files:
            analysis = self._load_analysis(file_path)
            if analysis is None:
                continue
            
            summary = analysis.get("summary", {})
            
            timestamps.append(timestamp.isoformat())
            total_events.append(summary.get("total_events", 0))
            failed_logins.append(summary.get("failed_logins", 0))
            successful_logins.append(summary.get("successful_logins", 0))
            unique_users.append(summary.get("unique_users", 0))
            login_success_rates.append(round(summary.get("login_success_rate", 0), 2))
        
        return {
            "trend_type": f"last_{hours}h",
            "timestamps": timestamps,
            "data_points": {
                "total_events": total_events,
                "failed_logins": failed_logins,
                "successful_logins": successful_logins,
                "unique_users": unique_users,
                "login_success_rate": login_success_rates
            },
            "summary": {
                "min_events": min(total_events) if total_events else 0,
                "max_events": max(total_events) if total_events else 0,
                "avg_events": round(sum(total_events) / len(total_events), 2) if total_events else 0,
                "min_failures": min(failed_logins) if failed_logins else 0,
                "max_failures": max(failed_logins) if failed_logins else 0,
                "avg_failures": round(sum(failed_logins) / len(failed_logins), 2) if failed_logins else 0,
                "data_points_count": len(timestamps)
            }
        }

    def get_week_over_week(self) -> Dict[str, Any]:
        """
        Get week-over-week comparison.
        
        Current week vs previous week metrics.
        
        Returns:
            Dictionary with WoW comparison data
        """
        now = datetime.now()
        current_week_start = now - timedelta(days=now.weekday())  # Monday of current week
        last_week_start = current_week_start - timedelta(days=7)
        
        # Get files for current week (last 7 days)
        current_week_files = [
            (ts, path) for ts, path in self.analysis_files
            if last_week_start <= ts <= now
        ]
        
        # Get files for previous week (7-14 days ago)
        two_weeks_ago = now - timedelta(days=14)
        last_week_files = [
            (ts, path) for ts, path in self.analysis_files
            if two_weeks_ago <= ts < last_week_start
        ]
        
        def aggregate_metrics(files: List[Tuple[datetime, Path]]) -> Dict[str, float]:
            """Aggregate metrics across multiple analysis files."""
            if not files:
                return {
                    "total_events": 0,
                    "failed_logins": 0,
                    "successful_logins": 0,
                    "avg_success_rate": 0
                }
            
            all_events = []
            all_failures = []
            all_successes = []
            all_rates = []
            
            for _, file_path in files:
                analysis = self._load_analysis(file_path)
                if analysis is None:
                    continue
                
                summary = analysis.get("summary", {})
                all_events.append(summary.get("total_events", 0))
                all_failures.append(summary.get("failed_logins", 0))
                all_successes.append(summary.get("successful_logins", 0))
                all_rates.append(summary.get("login_success_rate", 0))
            
            return {
                "total_events": sum(all_events),
                "failed_logins": sum(all_failures),
                "successful_logins": sum(all_successes),
                "avg_success_rate": round(sum(all_rates) / len(all_rates), 2) if all_rates else 0
            }
        
        current_metrics = aggregate_metrics(current_week_files)
        last_metrics = aggregate_metrics(last_week_files)
        
        # Calculate changes
        def calc_change(current: float, previous: float) -> Dict[str, Any]:
            """Calculate percentage change and direction."""
            if previous == 0:
                if current == 0:
                    pct = 0
                else:
                    pct = 100  # Growth from 0
            else:
                pct = round(((current - previous) / previous) * 100, 2)
            
            direction = "up" if pct > 0 else ("down" if pct < 0 else "stable")
            return {"change_percent": pct, "direction": direction}
        
        return {
            "current_week": current_metrics,
            "last_week": last_metrics,
            "comparison": {
                "events_change": calc_change(
                    current_metrics["total_events"],
                    last_metrics["total_events"]
                ),
                "failures_change": calc_change(
                    current_metrics["failed_logins"],
                    last_metrics["failed_logins"]
                ),
                "success_rate_change": calc_change(
                    current_metrics["avg_success_rate"],
                    last_metrics["avg_success_rate"]
                )
            }
        }

    def get_30day_trends(self) -> Dict[str, Any]:
        """
        Get 30-day trend analysis.
        
        Returns:
            Dictionary with 30-day trend data
        """
        return self.get_trend_data(hours=720)  # 30 days = 720 hours

    def get_7day_trends(self) -> Dict[str, Any]:
        """
        Get 7-day trend analysis.
        
        Returns:
            Dictionary with 7-day trend data
        """
        return self.get_trend_data(hours=168)  # 7 days = 168 hours
