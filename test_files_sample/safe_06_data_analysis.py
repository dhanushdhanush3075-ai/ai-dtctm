#!/usr/bin/env python3
"""
Data Analysis Utility
Legitimate data processing - No threats
"""

import csv
import statistics
from pathlib import Path

class DataAnalyzer:
    """Analyze data from CSV files"""

    def __init__(self, filename):
        """Initialize with CSV file"""
        self.filename = filename
        self.data = []
        self.load_data()

    def load_data(self):
        """Load data from CSV file"""
        if not Path(self.filename).exists():
            print(f"File not found: {self.filename}")
            return

        try:
            with open(self.filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.data.append(row)
            print(f"Loaded {len(self.data)} records")
        except Exception as e:
            print(f"Error loading data: {e}")

    def get_statistics(self, column):
        """Get statistics for a numeric column"""
        values = []
        for row in self.data:
            try:
                value = float(row.get(column, 0))
                values.append(value)
            except (ValueError, TypeError):
                continue

        if not values:
            return None

        return {
            "count": len(values),
            "sum": sum(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0,
            "min": min(values),
            "max": max(values),
        }

    def filter_by_verdict(self, verdict):
        """Filter records by verdict"""
        return [row for row in self.data if row.get("verdict") == verdict]

    def summary(self):
        """Print data summary"""
        print(f"\nData Summary:")
        print(f"Total records: {len(self.data)}")

        if self.data:
            verdicts = {}
            for row in self.data:
                verdict = row.get("verdict", "UNKNOWN")
                verdicts[verdict] = verdicts.get(verdict, 0) + 1

            print(f"Verdict distribution:")
            for verdict, count in sorted(verdicts.items()):
                percentage = (count / len(self.data)) * 100
                print(f"  {verdict}: {count} ({percentage:.1f}%)")

if __name__ == "__main__":
    # Example usage
    analyzer = DataAnalyzer("safe_04_data.csv")
    analyzer.summary()

    # Get statistics on risk scores
    stats = analyzer.get_statistics("risk_score")
    if stats:
        print(f"\nRisk Score Statistics:")
        print(f"  Mean: {stats['mean']:.2f}")
        print(f"  Min: {stats['min']:.2f}")
        print(f"  Max: {stats['max']:.2f}")
        print(f"  Median: {stats['median']:.2f}")

    # Filter clean files
    clean_files = analyzer.filter_by_verdict("CLEAN")
    print(f"\nClean files: {len(clean_files)}")
