"""Detect potentially impossible travel using approximate IP locations."""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TypeAlias

from loganalyzer.models import Alert, NormalizedEvent

EARTH_RADIUS_KM = 6371.0088


@dataclass(frozen=True, slots=True)
class Location:
    """Approximate synthetic location associated with an IP address."""

    latitude: float
    longitude: float
    label: str


LocationValue: TypeAlias = Location | tuple[float, float, str]


class ImpossibleTravelDetector:
    """Detect implausibly fast movement between successful user logins.

    Locations are supplied by the caller so this detector can later accept an
    offline GeoIP provider without changing its comparison logic. The mapping
    is intended for synthetic development data; IP geolocation is approximate
    and does not establish a user's physical location.
    """

    def __init__(
        self,
        locations: Mapping[str, LocationValue],
        max_speed_kmh: float = 900.0,
        min_elapsed_minutes: float = 0.0,
        min_distance_km: float = 100.0,
        ignore_private_ips: bool = False,
    ) -> None:
        if max_speed_kmh <= 0 or not math.isfinite(max_speed_kmh):
            raise ValueError("max_speed_kmh must be a finite positive number")
        if min_elapsed_minutes < 0 or not math.isfinite(min_elapsed_minutes):
            raise ValueError("min_elapsed_minutes must be a finite non-negative number")
        if min_distance_km < 0 or not math.isfinite(min_distance_km):
            raise ValueError("min_distance_km must be a finite non-negative number")

        self.locations = dict(locations)
        self.max_speed_kmh = max_speed_kmh
        self.min_elapsed_minutes = min_elapsed_minutes
        self.min_distance_km = min_distance_km
        self.ignore_private_ips = ignore_private_ips

    def detect(self, events: Iterable[NormalizedEvent]) -> Sequence[Alert]:
        by_user: defaultdict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if (
                event.event_type == "login_success"
                and event.status == "success"
                and event.user
                and event.src_ip
                and self._valid_timestamp(event.timestamp)
                and not self._should_ignore_ip(event.src_ip)
            ):
                by_user[event.user].append(event)

        alerts: list[Alert] = []
        for username, user_events in by_user.items():
            user_events.sort(key=self._timestamp_key)
            for first, second in zip(user_events, user_events[1:]):
                first_location = self._resolve(first.src_ip)
                second_location = self._resolve(second.src_ip)
                if first_location is None or second_location is None:
                    continue

                elapsed_seconds = (second.timestamp - first.timestamp).total_seconds()
                if elapsed_seconds <= 0 or elapsed_seconds < self.min_elapsed_minutes * 60:
                    continue

                distance_km = self.distance_km(first_location, second_location)
                if distance_km < self.min_distance_km:
                    continue

                speed_kmh = distance_km / (elapsed_seconds / 3600)
                if speed_kmh <= self.max_speed_kmh:
                    continue

                alerts.append(
                    Alert(
                        severity="MEDIUM",
                        title="Potential impossible travel detected",
                        summary=(
                            f"User '{username}' logged in from approximate locations "
                            f"{first_location.label} and {second_location.label} at an "
                            f"implied speed of {speed_kmh:.1f} km/h."
                        ),
                        evidence={
                            "username": username,
                            "first_source_ip": first.src_ip,
                            "second_source_ip": second.src_ip,
                            "first_login_timestamp": first.timestamp,
                            "second_login_timestamp": second.timestamp,
                            "first_location": first_location.label,
                            "second_location": second_location.label,
                            "distance_km": distance_km,
                            "elapsed_seconds": elapsed_seconds,
                            "implied_speed_kmh": speed_kmh,
                            "maximum_plausible_speed_kmh": self.max_speed_kmh,
                            "confidence": "low",
                            "geolocation_note": (
                                "Locations are synthetic and approximate; IP geolocation "
                                "does not establish physical location with certainty."
                            ),
                        },
                        recommended_actions=(
                            "Review both login events and verify whether the activity was authorized",
                            "Check VPN, proxy, and corporate egress usage before taking action",
                            "Review related authentication activity for the account",
                        ),
                        source_ips=(first.src_ip, second.src_ip),
                        time_start=first.timestamp,
                        time_end=second.timestamp,
                        detector="impossible_travel",
                        confidence="low",
                    )
                )
        return alerts

    @staticmethod
    def distance_km(first: Location, second: Location) -> float:
        """Return the great-circle distance between two locations."""
        first_latitude, first_longitude = math.radians(first.latitude), math.radians(first.longitude)
        second_latitude, second_longitude = math.radians(second.latitude), math.radians(second.longitude)
        latitude_delta = second_latitude - first_latitude
        longitude_delta = second_longitude - first_longitude
        haversine = (
            math.sin(latitude_delta / 2) ** 2
            + math.cos(first_latitude)
            * math.cos(second_latitude)
            * math.sin(longitude_delta / 2) ** 2
        )
        return EARTH_RADIUS_KM * 2 * math.asin(math.sqrt(min(1.0, haversine)))

    def _resolve(self, source_ip: str) -> Location | None:
        value = self.locations.get(source_ip)
        if value is None:
            return None
        if isinstance(value, Location):
            location = value
        else:
            try:
                location = Location(*value)
            except (TypeError, ValueError):
                return None
        try:
            valid_coordinates = all(
                math.isfinite(coordinate)
                for coordinate in (location.latitude, location.longitude)
            )
        except TypeError:
            return None
        if (
            not valid_coordinates
            or not -90 <= location.latitude <= 90
            or not -180 <= location.longitude <= 180
            or not isinstance(location.label, str)
            or not location.label
        ):
            return None
        return location

    def _should_ignore_ip(self, source_ip: str) -> bool:
        if not self.ignore_private_ips:
            return False
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return True
        return address.is_private or address.is_loopback or address.is_link_local

    @staticmethod
    def _valid_timestamp(timestamp: object) -> bool:
        return isinstance(timestamp, datetime)

    @staticmethod
    def _timestamp_key(event: NormalizedEvent) -> datetime:
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)