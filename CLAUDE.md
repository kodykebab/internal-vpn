# Internal VPN guide

Read [README.md](README.md) first. Adapted from the Pilot and Atlas guides.

## Code

- Put behavior on the DocType controllers. Expose it with `@frappe.whitelist` on class methods. Nothing outside Desk and the host agent calls the API, so do not add `api.py` or other module-level endpoints.
- Use classes that map to the domain. Do not spread related functions across files. Add a file only when it has a separate job, such as `host.py`, which runs alone on each host.
- `host.py` uses only the standard library. Do not import Frappe or other app modules there.
- Keep the code short and clear. Do not add helpers, wrappers or fallbacks without a real need.
- Reuse existing patterns and keep one owner for mutable state. Delete before adding.
- Keep permissions, validation, synchronization and cleanup when simplifying. Fail near the cause; retry only safe operations.
- Lock the network before reading or changing membership: `VPNNetwork.load_locked()`, then the member. Do not commit by hand; a conflicting change fails with `QueryDeadlockError` and can be retried.
- After the lock, read with `for_update`. Pilot turns MariaDB snapshot isolation off, so a plain read can return data from before the lock.
- Use Frappe APIs and hooks over our own mechanisms, and the query builder instead of raw SQL.
- Keep comments and docstrings short. Do not put comments or docstrings at the top of a file.
- Run `uvx ruff format` and `uvx ruff check`, the DocType tests with `bench run-tests --app internal_vpn`, and the tests in `tests/`. Put a new test in a DocType's `IntegrationTestCase` unless it needs real HTTP or several connections.

## Docs

- Keep docs short: `README.md`, `deploy/README.md` and this file. Do not add plan, context, evidence or history documents. Put that in commits and PRs.
- Use short, direct sentences, one paragraph per line, no em dashes. Describe current behavior only.
- Explain behavior once and link to it. Keep enough context to operate and change the app.

## Testing

- Test only on `ubuntu-dev`. Do not change existing interfaces, VM namespaces, sites, databases or disks.
- Do not touch staging or production. Do not push or create remote repositories without asking.
- Test ordinary behavior and meaningful failure cases. Report what ran and what remains unverified.
- Review every changed line for correctness and verbosity before handover. Leave unrelated changes and generated files alone.

## Commits

- Short lowercase subject, `type(scope): subject`. No AI co-author.
