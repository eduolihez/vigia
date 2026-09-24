# Ethics & Scope

> Skeleton — the full policy is written in Phase 9. Placeholder for now so the file
> exists from the first commit, per the brief's "definition of done" checklist.

## Summary (expand in Phase 9)

Vigía is built to be run **only** against domains the operator owns or is explicitly
authorized to test. Key guardrails (see `docs/decisions.md` and the brief's section 6
for the full rationale):

- Active scanning tools require domain-ownership verification via a DNS TXT record.
- The LLM planner can never expand scope beyond the target domain and its resolved
  infrastructure; it can only request tools, never arbitrary commands.
- Explicitly out of scope: exploit-grade vulnerability scanning, credential
  brute-forcing, aggressive fuzzing, and any personal/identity enrichment of emails.

Full ethics policy, permitted-use statement, and first-run consent copy land in
Phase 9.
