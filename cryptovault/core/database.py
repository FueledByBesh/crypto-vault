"""
Simple Database Module
Provides persistent storage using JSON files.
"""

import json
import os
from typing import Dict, Any
from threading import Lock


class SimpleDatabase:
    """
    Simple JSON-based database for persistence.
    Thread-safe with file locking.
    """

    def __init__(self, db_file: str):
        """
        Initialize database.

        Args:
            db_file: Path to the JSON database file
        """
        self.db_file = db_file
        self.data: Dict[str, Any] = {}
        self.lock = Lock()
        self.load()

    def load(self) -> None:
        """Load data from file."""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
            except Exception as e:
                print(f"Error loading database: {e}")
                self.data = {}
        else:
            self.data = {}

    def save(self) -> None:
        """Save data to file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.db_file), exist_ok=True)

            with self.lock:
                with open(self.db_file, 'w', encoding='utf-8') as f:
                    json.dump(self.data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving database: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get value by key."""
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set value by key."""
        self.data[key] = value
        self.save()

    def delete(self, key: str) -> bool:
        """Delete key-value pair."""
        if key in self.data:
            del self.data[key]
            self.save()
            return True
        return False

    def keys(self) -> list:
        """Get all keys."""
        return list(self.data.keys())

    def values(self) -> list:
        """Get all values."""
        return list(self.data.values())

    def items(self):
        """Get all key-value pairs."""
        return self.data.items()

    def clear(self) -> None:
        """Clear all data."""
        self.data.clear()
        self.save()