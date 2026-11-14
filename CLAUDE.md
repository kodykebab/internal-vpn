# Internal VPN guide

Read [README.md](README.md) first. Follow these rules for every change.

## Code

- Put behavior on the DocType controllers. Expose it with `@frappe.whitelist` on class methods. Nothing outside Desk and the host agent calls the API, so do not add `api.py` or other module-level endpoints.
- Use classes that map to the domain. Do not spread related functions across files. Add a file only when it has a separate job, such as `host.py`, which runs alone on each host.
- `host.py` uses only the standard library. Do not import Frappe or other app modules there.
- Keep the code short and clear. Do not add helpers, wrappers or fallbacks without a real need.
- Start every membership change and membership read with `VPN Network.lock()`. It commits first, so write nothing before it; every read after it sees current membership.
- Keep comments and docstrings short. Do not put comments or docstrings at the top of a file.
- Run `uvx ruff format` and `uvx ruff check`, and the unit tests in `tests/`.

## Docs

- Keep docs short: `README.md`, `deploy/README.md` and this file. Do not add plan, context, evidence or history documents. Put that in commits and PRs.
- Use short, direct sentences, one paragraph per line, no em dashes. Describe current behavior only.

## Testing

- Test only on `ubuntu-dev`. Do not change existing interfaces, VM namespaces, sites, databases or disks.
- Do not touch staging or production. Do not push or create remote repositories without asking.

## Commits

- Short lowercase subject, `type(scope): subject`. No AI co-author.
