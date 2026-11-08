# ad-group-membership-auditor

Audit AD-style group membership from a CSV: privileged groups are listed with their members, and any user in more than one privileged group is flagged HIGH EXPOSURE.

## How to run

```sh
python3 main.py membership.csv
```

## Example output

```
Domain Admins [privileged]: ali, sara
Schema Admins [privileged]: ali
ali: HIGH EXPOSURE (2 privileged groups: Domain Admins, Schema Admins)
```

Standard library only. Run the tests with `python3 -m unittest discover`.
