"""Deterministic correlation-based privilege escalation detection.

Detects:
1. Special privileges assigned to a logon (Windows 4672).
2. New account creation (Windows 4720).
3. Privileged security-group membership changes (Windows 4728/4732).
4. SSH ``sudo``/``su`` activity.
5. Process creation (Windows 4688) shortly following a suspicious login or
   privilege-related event.
6. Correlated chains linking account creation, privileged-group membership,
   and privileged activity within a configured window.

Findings never claim confirmed privilege escalation; alerts describe
"potential" privilege escalation and preserve the raw evidence that
supports the correlation so an analyst can verify it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta

from loganalyzer.models import Alert, NormalizedEvent

DEFAULT_PRIVILEGED_GROUPS = frozenset(
    {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "backup operators",
        "server operators",
        "account operators",
        "print operators",
    }
)

_REVIEW_RECOMMENDATIONS = (
    "Review the affected account's recent authentication and privilege history",
    "Verify that the account creation, group change, or privileged action was authorized",
)
_ESCALATION_RECOMMENDATIONS = _REVIEW_RECOMMENDATIONS + (
    "Confirm the account still requires the privileges or group membership it received",
    "Consider requiring re-verification of the account pending manual investigation",
)


@dataclass(frozen=True, slots=True)
class _Record:
    """A privilege-relevant event paired with the identity used to correlate it."""

    event: NormalizedEvent
    account: str | None
    host: str | None
    src_ip: str | None
    event_id: str | None
    group_name: str | None = None
    process_name: str | None = None
    process_id: object | None = None


class PrivilegeEscalationDetector:
    """Correlate privileged-account activity into deterministic escalation alerts.

    A lone 4672 (special privileges assigned to a new logon) is a routine,
    expected event on most systems and is never automatically HIGH or
    CRITICAL by itself. Severity only escalates when 4672 is corroborated by
    other evidence, such as a nearby suspicious login, a newly created
    account, privileged-group membership, or a related process creation.
    """

    def __init__(
        self,
        correlation_window_minutes: int = 30,
        process_correlation_window_minutes: int = 15,
        privileged_groups: Iterable[str] | None = None,
        known_administrative_accounts: Iterable[str] | None = None,
    ) -> None:
        if correlation_window_minutes <= 0:
            raise ValueError("correlation_window_minutes must be positive")
        if process_correlation_window_minutes <= 0:
            raise ValueError("process_correlation_window_minutes must be positive")

        self.correlation_window_minutes = correlation_window_minutes
        self.correlation_window = timedelta(minutes=correlation_window_minutes)
        self.process_correlation_window_minutes = process_correlation_window_minutes
        self.process_correlation_window = timedelta(minutes=process_correlation_window_minutes)
        self.privileged_groups = frozenset(
            group.lower() for group in (privileged_groups or DEFAULT_PRIVILEGED_GROUPS)
        )
        # Accounts known to perform routine administrative work; involvement caps
        # escalation one severity level below what the correlation would otherwise assign.
        self.known_administrative_accounts = frozenset(
            account.lower() for account in (known_administrative_accounts or ())
        )

    def detect(self, events: Iterable[NormalizedEvent]) -> Sequence[Alert]:
        ordered = sorted(events, key=lambda event: event.timestamp)

        created = [
            self._as_record(event) for event in ordered if event.event_type == "user_created"
        ]
        groups = [
            record
            for event in ordered
            if event.event_type == "privileged_group_membership"
            for record in (self._group_record(event),)
            if record is not None
        ]
        privilege_assignments = [
            self._as_record(event)
            for event in ordered
            if event.event_type == "privilege_assignment"
        ]
        process_creations = [
            self._process_record(event) for event in ordered if event.event_type == "process_creation"
        ]
        sudo_su = [
            self._as_record(event)
            for event in ordered
            if event.log_type == "ssh" and event.event_type == "privilege_action"
        ]
        suspicious_logins = [
            self._as_record(event) for event in ordered if event.event_type == "login_failure"
        ]

        activities = sorted(
            privilege_assignments + process_creations + sudo_su,
            key=lambda record: record.event.timestamp,
        )

        used_created: set[int] = set()
        used_groups: set[int] = set()
        used_activity: set[int] = set()

        alerts: list[Alert] = []

        # Stage 1: full chain -> account created, added to a privileged group,
        # then privileged activity, all within the correlation window.
        for group in groups:
            if id(group.event) in used_groups:
                continue
            creator = self._find_correlated(created, group, self.correlation_window, used_created, "prior")
            if creator is None:
                continue
            activity = self._find_correlated(activities, group, self.correlation_window, used_activity, "next")
            if activity is None:
                continue
            alerts.append(self._chain_alert(creator, group, activity))
            used_created.add(id(creator.event))
            used_groups.add(id(group.event))
            used_activity.add(id(activity.event))

        # Stage 2: account created -> added to a privileged group (no follow-on activity observed).
        for group in groups:
            if id(group.event) in used_groups:
                continue
            creator = self._find_correlated(created, group, self.correlation_window, used_created, "prior")
            if creator is None:
                continue
            alerts.append(self._account_then_group_alert(creator, group))
            used_created.add(id(creator.event))
            used_groups.add(id(group.event))

        # Stage 3: privileged-group membership -> privileged activity (no observed account creation).
        for group in groups:
            if id(group.event) in used_groups:
                continue
            activity = self._find_correlated(activities, group, self.correlation_window, used_activity, "next")
            if activity is None:
                continue
            alerts.append(self._group_then_activity_alert(group, activity))
            used_groups.add(id(group.event))
            used_activity.add(id(activity.event))

        # Stage 4: account created -> privileged activity directly (no group membership observed).
        for creator in created:
            if id(creator.event) in used_created:
                continue
            activity = self._find_correlated(activities, creator, self.correlation_window, used_activity, "next")
            if activity is None:
                continue
            alerts.append(self._account_then_activity_alert(creator, activity))
            used_created.add(id(creator.event))
            used_activity.add(id(activity.event))

        # Stage 5: process creation following a nearby suspicious login or privilege-related event.
        login_candidates = suspicious_logins + privilege_assignments
        for process in process_creations:
            if id(process.event) in used_activity:
                continue
            login = self._find_correlated(
                login_candidates, process, self.process_correlation_window, set(), "prior"
            )
            if login is None:
                continue
            alerts.append(self._process_after_login_alert(login, process))
            used_activity.add(id(process.event))
            used_activity.add(id(login.event))

        # Stage 6: privilege assignment (4672) following a nearby suspicious login,
        # when it was not already explained by an account/group correlation above.
        for assignment in privilege_assignments:
            if id(assignment.event) in used_activity:
                continue
            login = self._find_correlated(
                suspicious_logins, assignment, self.process_correlation_window, set(), "prior"
            )
            if login is None:
                continue
            alerts.append(self._privilege_assignment_after_login_alert(login, assignment))
            used_activity.add(id(assignment.event))

        # Stage 7: isolated signals for anything left unattributed.
        for creator in created:
            if id(creator.event) not in used_created:
                alerts.append(self._isolated_account_created_alert(creator))
        for group in groups:
            if id(group.event) not in used_groups:
                alerts.append(self._isolated_group_alert(group))
        for assignment in privilege_assignments:
            if id(assignment.event) not in used_activity:
                alerts.append(self._isolated_privilege_assignment_alert(assignment))
        for action in sudo_su:
            if id(action.event) not in used_activity:
                alerts.append(self._isolated_sudo_su_alert(action))

        alerts.sort(key=lambda alert: alert.time_start or alert.time_end)
        return alerts

    # -- record extraction -------------------------------------------------

    @staticmethod
    def _event_id(event: NormalizedEvent) -> str | None:
        event_id = event.metadata.get("event_id")
        if event_id is not None:
            return event_id
        if event.log_type == "ssh" and event.event_type == "privilege_action":
            return event.metadata.get("action")
        return None

    def _as_record(self, event: NormalizedEvent) -> _Record:
        return _Record(
            event=event,
            account=event.user,
            host=event.metadata.get("computer"),
            src_ip=event.src_ip,
            event_id=self._event_id(event),
        )

    def _group_record(self, event: NormalizedEvent) -> _Record | None:
        group_name = (
            event.metadata.get("group_name") or event.metadata.get("target_user") or event.user
        )
        if not group_name or group_name.lower() not in self.privileged_groups:
            return None
        account = event.metadata.get("member_name") or event.user
        return _Record(
            event=event,
            account=account,
            host=event.metadata.get("computer"),
            src_ip=event.src_ip,
            event_id=self._event_id(event),
            group_name=group_name,
        )

    def _process_record(self, event: NormalizedEvent) -> _Record:
        return _Record(
            event=event,
            account=event.user,
            host=event.metadata.get("computer"),
            src_ip=event.src_ip,
            event_id=self._event_id(event),
            process_name=event.metadata.get("new_process_name"),
            process_id=event.metadata.get("new_process_id"),
        )

    # -- correlation ---------------------------------------------------

    @staticmethod
    def _same_context(first: NormalizedEvent, second: NormalizedEvent) -> bool:
        host_first = first.metadata.get("computer")
        host_second = second.metadata.get("computer")
        if host_first and host_second:
            return host_first.lower() == host_second.lower()
        if host_first or host_second:
            if first.src_ip and second.src_ip:
                return first.src_ip == second.src_ip
            return False
        if first.src_ip and second.src_ip:
            return first.src_ip == second.src_ip
        return True

    def _find_correlated(
        self,
        candidates: list[_Record],
        target: _Record,
        window: timedelta,
        used_ids: set[int],
        direction: str,
    ) -> _Record | None:
        best: _Record | None = None
        for candidate in candidates:
            if id(candidate.event) in used_ids:
                continue
            if candidate.account is None or target.account is None:
                continue
            if candidate.account.lower() != target.account.lower():
                continue
            if not self._same_context(candidate.event, target.event):
                continue
            if direction == "prior":
                delta = target.event.timestamp - candidate.event.timestamp
            else:
                delta = candidate.event.timestamp - target.event.timestamp
            if delta < timedelta(0) or delta > window:
                continue
            if best is None:
                best = candidate
            elif direction == "prior" and candidate.event.timestamp > best.event.timestamp:
                best = candidate
            elif direction == "next" and candidate.event.timestamp < best.event.timestamp:
                best = candidate
        return best

    # -- alert construction ----------------------------------------------

    def _base_evidence(self, *records: _Record) -> dict[str, object]:
        related_event_ids = [record.event_id for record in records if record.event_id]
        return {
            "related_event_ids": related_event_ids,
            "correlation_window_minutes": self.correlation_window_minutes,
        }

    @staticmethod
    def _source_ips(*records: _Record) -> tuple[str, ...]:
        ips = {record.src_ip for record in records if record.src_ip}
        return tuple(sorted(ips))

    def _is_trusted(self, *accounts: str | None) -> bool:
        return any(
            account is not None and account.lower() in self.known_administrative_accounts
            for account in accounts
        )

    def _severity_for(self, base_severity: str, *accounts: str | None) -> str:
        if not self._is_trusted(*accounts):
            return base_severity
        downgrade = {"CRITICAL": "HIGH", "HIGH": "MEDIUM"}
        return downgrade.get(base_severity, base_severity)

    def _isolated_account_created_alert(self, creator: _Record) -> Alert:
        event = creator.event
        evidence = self._base_evidence(creator)
        evidence.update(
            {
                "rule": "isolated_account_created",
                "event_id": creator.event_id,
                "username": creator.account,
                "computer": creator.host,
                "source_ip": creator.src_ip,
            }
        )
        return Alert(
            severity="LOW",
            title="New user account created",
            summary=(
                f"Account '{creator.account}' was created on {creator.host or 'an unknown host'} "
                "with no correlated privileged-group membership or privileged activity observed."
            ),
            evidence=evidence,
            recommended_actions=_REVIEW_RECOMMENDATIONS,
            source_ips=self._source_ips(creator),
            time_start=event.timestamp,
            time_end=event.timestamp,
            detector="privilege_escalation",
            confidence="low",
        )

    def _isolated_privilege_assignment_alert(self, assignment: _Record) -> Alert:
        # 4672 alone is a routine, expected event on most systems; it is not
        # escalated to HIGH/CRITICAL without corroborating evidence.
        event = assignment.event
        evidence = self._base_evidence(assignment)
        evidence.update(
            {
                "rule": "isolated_privilege_assignment",
                "event_id": assignment.event_id,
                "username": assignment.account,
                "computer": assignment.host,
                "source_ip": assignment.src_ip,
                "privileges": event.metadata.get("privileges"),
                "known_administrative_account": self._is_trusted(assignment.account),
            }
        )
        return Alert(
            severity="LOW",
            title="Special privileges assigned to a new logon",
            summary=(
                f"Special privileges were assigned to a new logon for '{assignment.account}' on "
                f"{assignment.host or 'an unknown host'}. No corroborating suspicious login, account "
                "creation, or privileged-group membership was observed, so this is reported as an "
                "informational finding rather than confirmed privilege escalation."
            ),
            evidence=evidence,
            recommended_actions=_REVIEW_RECOMMENDATIONS,
            source_ips=self._source_ips(assignment),
            time_start=event.timestamp,
            time_end=event.timestamp,
            detector="privilege_escalation",
            confidence="low",
        )

    def _isolated_group_alert(self, group: _Record) -> Alert:
        event = group.event
        evidence = self._base_evidence(group)
        evidence.update(
            {
                "rule": "isolated_privileged_group_membership",
                "event_id": group.event_id,
                "username": group.account,
                "group_name": group.group_name,
                "computer": group.host,
                "source_ip": group.src_ip,
            }
        )
        return Alert(
            severity="MEDIUM",
            title="Account added to a privileged group",
            summary=(
                f"Account '{group.account}' was added to privileged group '{group.group_name}' on "
                f"{group.host or 'an unknown host'} with no correlated account creation or follow-on "
                "activity observed."
            ),
            evidence=evidence,
            recommended_actions=_REVIEW_RECOMMENDATIONS,
            source_ips=self._source_ips(group),
            time_start=event.timestamp,
            time_end=event.timestamp,
            detector="privilege_escalation",
            confidence="medium",
        )

    def _isolated_sudo_su_alert(self, action: _Record) -> Alert:
        event = action.event
        kind = event.metadata.get("action", "privilege_action")
        evidence = self._base_evidence(action)
        evidence.update(
            {
                "rule": f"isolated_{kind}_activity",
                "event_id": action.event_id,
                "username": action.account,
                "source_ip": action.src_ip,
                "action": kind,
            }
        )
        return Alert(
            severity="LOW",
            title=f"SSH '{kind}' activity observed",
            summary=(
                f"Account '{action.account}' used '{kind}' with no correlated account creation, "
                "privileged-group membership, or further activity observed."
            ),
            evidence=evidence,
            recommended_actions=_REVIEW_RECOMMENDATIONS,
            source_ips=self._source_ips(action),
            time_start=event.timestamp,
            time_end=event.timestamp,
            detector="privilege_escalation",
            confidence="low",
        )

    def _activity_evidence_fields(self, activity: _Record) -> dict[str, object]:
        fields: dict[str, object] = {"activity_event_id": activity.event_id}
        if activity.process_name is not None:
            fields["process_name"] = activity.process_name
        if activity.process_id is not None:
            fields["process_id"] = activity.process_id
        action = activity.event.metadata.get("action")
        if action is not None:
            fields["action"] = action
        return fields

    def _account_then_group_alert(self, creator: _Record, group: _Record) -> Alert:
        severity = self._severity_for("HIGH", creator.account, group.account)
        evidence = self._base_evidence(creator, group)
        evidence.update(
            {
                "rule": "account_created_then_privileged_group_membership",
                "username": group.account,
                "group_name": group.group_name,
                "computer": group.host or creator.host,
                "created_event_id": creator.event_id,
                "group_event_id": group.event_id,
                "account_created_at": creator.event.timestamp,
                "group_membership_at": group.event.timestamp,
                "known_administrative_account": self._is_trusted(creator.account, group.account),
            }
        )
        return Alert(
            severity=severity,
            title="New account added to a privileged group",
            summary=(
                "Potential privilege escalation detected: account "
                f"'{group.account}' was created and then added to privileged group "
                f"'{group.group_name}' within {self.correlation_window_minutes} minutes."
            ),
            evidence=evidence,
            recommended_actions=_ESCALATION_RECOMMENDATIONS,
            source_ips=self._source_ips(creator, group),
            time_start=creator.event.timestamp,
            time_end=group.event.timestamp,
            detector="privilege_escalation",
            confidence="high",
        )

    def _group_then_activity_alert(self, group: _Record, activity: _Record) -> Alert:
        severity = self._severity_for("HIGH", group.account, activity.account)
        evidence = self._base_evidence(group, activity)
        evidence.update(
            {
                "rule": "privileged_group_membership_followed_by_activity",
                "username": group.account,
                "group_name": group.group_name,
                "computer": group.host or activity.host,
                "group_event_id": group.event_id,
                "group_membership_at": group.event.timestamp,
                "activity_at": activity.event.timestamp,
                "known_administrative_account": self._is_trusted(group.account, activity.account),
                **self._activity_evidence_fields(activity),
            }
        )
        return Alert(
            severity=severity,
            title="Privileged activity following group membership change",
            summary=(
                "Potential privilege escalation detected: account "
                f"'{group.account}' performed privileged activity within "
                f"{self.correlation_window_minutes} minutes of being added to privileged group "
                f"'{group.group_name}'."
            ),
            evidence=evidence,
            recommended_actions=_ESCALATION_RECOMMENDATIONS,
            source_ips=self._source_ips(group, activity),
            time_start=group.event.timestamp,
            time_end=activity.event.timestamp,
            detector="privilege_escalation",
            confidence="high",
        )

    def _account_then_activity_alert(self, creator: _Record, activity: _Record) -> Alert:
        severity = self._severity_for("HIGH", creator.account, activity.account)
        evidence = self._base_evidence(creator, activity)
        evidence.update(
            {
                "rule": "privileged_activity_following_new_account",
                "username": creator.account,
                "computer": creator.host or activity.host,
                "created_event_id": creator.event_id,
                "account_created_at": creator.event.timestamp,
                "activity_at": activity.event.timestamp,
                "known_administrative_account": self._is_trusted(creator.account, activity.account),
                **self._activity_evidence_fields(activity),
            }
        )
        return Alert(
            severity=severity,
            title="Privileged activity following new account creation",
            summary=(
                "Potential privilege escalation detected: newly created account "
                f"'{creator.account}' performed privileged activity within "
                f"{self.correlation_window_minutes} minutes of creation."
            ),
            evidence=evidence,
            recommended_actions=_ESCALATION_RECOMMENDATIONS,
            source_ips=self._source_ips(creator, activity),
            time_start=creator.event.timestamp,
            time_end=activity.event.timestamp,
            detector="privilege_escalation",
            confidence="high",
        )

    def _chain_alert(self, creator: _Record, group: _Record, activity: _Record) -> Alert:
        severity = self._severity_for("CRITICAL", creator.account, group.account, activity.account)
        evidence = self._base_evidence(creator, group, activity)
        evidence.update(
            {
                "rule": "privilege_escalation_chain",
                "username": group.account,
                "group_name": group.group_name,
                "computer": group.host or creator.host or activity.host,
                "created_event_id": creator.event_id,
                "group_event_id": group.event_id,
                "account_created_at": creator.event.timestamp,
                "group_membership_at": group.event.timestamp,
                "activity_at": activity.event.timestamp,
                "known_administrative_account": self._is_trusted(
                    creator.account, group.account, activity.account
                ),
                **self._activity_evidence_fields(activity),
            }
        )
        return Alert(
            severity=severity,
            title="New account escalated to privileged activity",
            summary=(
                "Potential privilege escalation detected: account "
                f"'{group.account}' was created, added to privileged group '{group.group_name}', "
                "and performed privileged activity, all within "
                f"{self.correlation_window_minutes} minutes."
            ),
            evidence=evidence,
            recommended_actions=_ESCALATION_RECOMMENDATIONS,
            source_ips=self._source_ips(creator, group, activity),
            time_start=creator.event.timestamp,
            time_end=activity.event.timestamp,
            detector="privilege_escalation",
            confidence="high",
        )

    def _process_after_login_alert(self, login: _Record, process: _Record) -> Alert:
        severity = self._severity_for("HIGH", login.account, process.account)
        evidence = {
            "rule": "process_creation_after_suspicious_login",
            "related_event_ids": [
                event_id for event_id in (login.event_id, process.event_id) if event_id
            ],
            "process_correlation_window_minutes": self.process_correlation_window_minutes,
            "username": process.account,
            "computer": process.host or login.host,
            "source_ip": process.src_ip or login.src_ip,
            "login_event_id": login.event_id,
            "login_at": login.event.timestamp,
            "process_event_id": process.event_id,
            "process_at": process.event.timestamp,
            "process_name": process.process_name,
            "process_id": process.process_id,
            "known_administrative_account": self._is_trusted(login.account, process.account),
        }
        return Alert(
            severity=severity,
            title="Process creation following a suspicious login or privileged event",
            summary=(
                "Potential privilege escalation detected: process "
                f"'{process.process_name or 'unknown'}' was created for account "
                f"'{process.account}' within {self.process_correlation_window_minutes} minutes "
                "of a suspicious login or privilege-related event."
            ),
            evidence=evidence,
            recommended_actions=_ESCALATION_RECOMMENDATIONS,
            source_ips=self._source_ips(login, process),
            time_start=login.event.timestamp,
            time_end=process.event.timestamp,
            detector="privilege_escalation",
            confidence="medium",
        )

    def _privilege_assignment_after_login_alert(self, login: _Record, assignment: _Record) -> Alert:
        severity = self._severity_for("HIGH", login.account, assignment.account)
        evidence = {
            "rule": "privilege_assignment_after_suspicious_login",
            "related_event_ids": [
                event_id for event_id in (login.event_id, assignment.event_id) if event_id
            ],
            "process_correlation_window_minutes": self.process_correlation_window_minutes,
            "event_id": assignment.event_id,
            "username": assignment.account,
            "computer": assignment.host or login.host,
            "source_ip": assignment.src_ip or login.src_ip,
            "login_event_id": login.event_id,
            "login_at": login.event.timestamp,
            "assignment_event_id": assignment.event_id,
            "assignment_at": assignment.event.timestamp,
            "privileges": assignment.event.metadata.get("privileges"),
            "known_administrative_account": self._is_trusted(login.account, assignment.account),
        }
        return Alert(
            severity=severity,
            title="Special privileges assigned following a suspicious login",
            summary=(
                "Potential privilege escalation detected: special privileges were assigned to a new "
                f"logon for account '{assignment.account}' within "
                f"{self.process_correlation_window_minutes} minutes of a suspicious authentication event."
            ),
            evidence=evidence,
            recommended_actions=_ESCALATION_RECOMMENDATIONS,
            source_ips=self._source_ips(login, assignment),
            time_start=login.event.timestamp,
            time_end=assignment.event.timestamp,
            detector="privilege_escalation",
            confidence="medium",
        )
