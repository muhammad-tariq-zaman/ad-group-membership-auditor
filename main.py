"""Audit AD-style group membership: flag users in privileged groups.

Usage: python3 main.py membership.csv
CSV columns: user,group,privileged (yes/no).
Privileged groups are listed with their members, most members first.
A user who belongs to more than one privileged group is flagged
HIGH EXPOSURE, since that account is a bigger target if compromised.
"""
import argparse, csv, sys
from collections import defaultdict

def audit(rows):
    privileged = defaultdict(list)
    user_groups = defaultdict(list)
    for row in rows:
        if row["privileged"].strip().lower() != "yes":
            continue
        group = row["group"].strip()
        user = row["user"].strip()
        privileged[group].append(user)
        user_groups[user].append(group)
    groups = sorted(privileged.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    multi = sorted((u, g) for u, g in user_groups.items() if len(g) > 1)
    return groups, multi

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    args = parser.parse_args(argv)
    with open(args.path, newline="", encoding="utf-8") as f:
        groups, multi = audit(list(csv.DictReader(f)))
    for group, users in groups:
        print(f"{group} [privileged]: {', '.join(sorted(users))}")
    for user, groups_ in multi:
        print(f"{user}: HIGH EXPOSURE ({len(groups_)} privileged groups: {', '.join(sorted(groups_))})")
    if not groups:
        print("No privileged group members found.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
