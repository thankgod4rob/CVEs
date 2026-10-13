# Komodo Disclosures

## What is "Komodo"?

In these findings, **Komodo** is [moghtech/komodo](https://github.com/moghtech/komodo), an open-source, self-hosted infrastructure management platform. It is used to build, deploy and manage Docker containers, Docker Compose stacks, git repos and scripts across a fleet of servers. It is a Portainer-style control plane with a web UI and an API.

It has two main components:

- **Komodo Core** is the web UI, API (`/auth`, `/read`, `/write`, `/execute`, default port 9120) and MongoDB-backed state. It handles users, permissions, JWT sessions and the Actions feature (user-authored TypeScript run by Deno).
- **Komodo Periphery** is the agent on each managed host (default port 8120). It receives instructions from Core and runs `docker`, `docker compose` and `git` commands, typically as root and often with `/var/run/docker.sock` mounted.

Core holds the credentials and the authority, and Periphery holds the root shell. So most findings here amount to the same thing: **a Komodo user with limited rights, or no rights at all, gets code execution as root on the managed Docker hosts.**

The original 15 disclosures covered two groups (FIX-02 has since been merged into FIX-01, and CONF-01 was added, see the update note above):

- **13 issues in v2.3.3** (the `ghcr.io/moghtech/komodo-core:2` image). These are INJ-01 to INJ-07, XSS-01, AUTH-01/03/06/07 and AUTHZ-02.
- **A Periphery v1.19.5-and-earlier issue** (FIX-01, which folds in the interactive-PTY terminal WebSocket formerly tracked as FIX-02). This was fixed in v2.0.0 but never backported. The v1 line has no formal end-of-life notice: the last v1 release was 2025-09-27, there is no later v1 tag, and v2 release notes only say "Still running v1? Check out the Komodo v2 upgrade guide."

All were credited to Robert Childers and disclosed to the vendor on 2026-10-06. Proofs of concept and the formal records are in [`komodo-pocs/`](komodo-pocs/) (records in [`komodo-pocs/reporting/`](komodo-pocs/reporting/)).

> **Update (2026-10-12): this document has been reconciled with live verification.** Several verdicts in the original review changed after testing in Docker, and the per-finding records in `komodo-pocs/reporting/` are now the authoritative source. Material changes: **INJ-07** is a confirmed root RCE (folded into INJ-01, same CVE), **AUTHZ-02** flipped to assignable (disabled users can manage their own account via `/auth/manage`), **INJ-05** code execution was confirmed (via `core.hooksPath`), **XSS-01** execution + token theft was confirmed in a browser, and a new finding **CONF-01** (default `KOMODO_JWT_SECRET` placeholder → pre-auth token forgery) was added. Scores were recomputed; note the earlier "AUTH-01 without `S:C` = 7.1" was an arithmetic error, it is **8.1**.

### Caveats on this document

- **Rule citations are to the CVE Program's CNA Operational Rules v4.2.0** (approved 2026-08-20, effective 2026-08-25), read from [CNA_RULES_v4.2.0.pdf](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.2.0.pdf). "Rule 4.1.3" and so on refer to that document.
- **Some assigned CVSS strings look wrong.** Base scores below were computed from the vectors in each disclosure. In two cases the severity label doesn't match the vector, and a few vectors look off (details below).

## Who assigns the CVE IDs

The CNA for these findings is the **AHA! CNA**, a research CNA authorized to assign CVE IDs. The final decision on every ID below belongs to AHA!. Komodo's maintainers (moghtech) are the vendor, they are **not** a CNA, and they are being kept informed and consulted on assignment. Because the vendor is not a CNA, it has no right of first refusal (Rule 4.2.1.1), so AHA! is the CNA with the most appropriate scope.

Throughout this document, "the CNA" means AHA!, and "the vendor" means the Komodo maintainers. Wherever a recommendation below depends on the vendor, it is input to AHA!'s judgment and not a veto. Rule 4.1.1 says CNAs SHOULD agree when a Supplier determines that a vulnerability exists, and the rules give the CNA the call otherwise (4.4).

## How the CVE recommendations were made

The CNA Rules use few "MUST"s and many "SHOULD"s. These are the rules that matter for this set:

- **What counts as a vulnerability (4.1).** The Glossary definition quoted in 4.1 is "an instance of one or more weaknesses in a Product that can be exploited, causing a negative impact to confidentiality, integrity, or availability", or conditions that allow violating an explicit or implicit security policy.
  - 4.1.1: if the Supplier decides a vulnerability exists, CNAs SHOULD agree.
  - 4.1.2: conditions that do not lead to a security impact SHOULD NOT be determined to be vulnerabilities.
- **Insecure defaults (4.1.3).** CNAs SHOULD determine insecure default configuration settings to be vulnerabilities, with these refinements:
  - 4.1.3.2: defaults that introduce under-documented, surprising or unexpected security behavior SHOULD be vulnerabilities.
  - 4.1.3.3: defaults that enable direct exploitation SHOULD be vulnerabilities.
  - 4.1.3.4: consistently well-documented, widely known defaults MAY be determined not to be vulnerabilities.
  - 4.1.3.5: non-default changes made by an authorized user SHOULD NOT be.
  - 4.1.3.6: if the Supplier changes a default to address a vulnerability, CNAs SHOULD agree it is one.
- **Resource exhaustion (4.1.5).** Brute-force resource exhaustion SHOULD NOT be a vulnerability, but failing to implement common defenses MAY be (the rule cites CWE-770).
- **Counting vulnerabilities (4.1.9, 4.1.10, 4.2.6, 4.2.11, 4.2.12, 4.2.15).** Separate IDs for independently fixable vulnerabilities. Interdependent conditions are one vulnerability. If a CNA is uncertain whether two issues are independently fixable, it SHOULD assign a single ID. Fully interdependent vulnerabilities MUST NOT get different IDs.
- **End-of-life products (4.1.12, 4.2.17.1, 4.2.17.7).** EOL status alone is not a vulnerability and is not a reason to assign. But CNAs SHOULD assign IDs for vulnerabilities in EOL products and MUST tag records covering only unfixed products `unsupported-when-assigned`.
- **Fixes (4.2.7).** IDs go to vulnerabilities, not fixes, whether or not a fix exists.
- **Doubt (4.4.3).** If a CNA can't make a clear decision after a good-faith effort, it SHOULD err on the side of assignment.
- **Duplicates (4.2.16.7, 4.2.16.8).** CNAs SHOULD ask requesters whether they already requested an ID elsewhere.

Where a recommendation depends on the vendor's position, the table and the finding say so.

## Summary

Scores were computed from the vector. "As labelled" is what the disclosure says.

| ID | Issue | CWE | CVSS 3.1 | Score | CVE? |
|---|---|---|---|---|---|
| [FIX-01](komodo-pocs/reporting/CVE-PRE-2.0-KOMODO-FIX-01.md) | Periphery v1 unauthenticated HTTP RPC + terminal WebSocket (incl. former FIX-02 interactive root PTY) | CWE-306 | [AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) | 10.0 | **Yes** |
| [INJ-01](komodo-pocs/reporting/CVE-KOMODO-INJ-01.md) | Deployment `docker run` shell injection (`extra_args`, `command`, `network`, `environment`) | CWE-78 | [AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) | 9.9 | **Yes** (one ID; former INJ-02/03/07 merged in) |
| [INJ-04](komodo-pocs/reporting/CWE-KOMODO-INJ-04.md) | Stack `project_name` shell sink (validated upstream in the pipeline) | none (not a vulnerability) | n/a, the author's vector is [AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H) | n/a | **No** (not a vulnerability) |
| [INJ-05](komodo-pocs/reporting/CVE-KOMODO-INJ-05.md) | git `branch` argument injection | CWE-88 | [AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) | 9.9 | **Yes** |
| [INJ-06](komodo-pocs/reporting/CWE-KOMODO-INJ-06.md) | Deno Action host RCE and secret exposure | CWE-250 (primary) | [AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H) | 7.2 | **Probably not** |
| [XSS-01](komodo-pocs/reporting/CVE-KOMODO-XSS-01.md) | `/login?backto=` `javascript:` URI | CWE-79 | [AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N) | 9.3 | **Yes** |
| [AUTH-01](komodo-pocs/reporting/CVE-KOMODO-AUTH-01.md) | Cleartext HTTP by default, 24h JWT | CWE-319 | [AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) | 8.1 | **Yes** (documented defaults can still be CVEs) |
| [AUTH-03](komodo-pocs/reporting/CVE-KOMODO-AUTH-03.md) | Signup not rate-limited | CWE-770 | [AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) | 5.3 | **Optional** (permitted by 4.1.5; low-severity record) |
| [AUTH-06](komodo-pocs/reporting/CVE-KOMODO-AUTH-06.md) | No JWT or session revocation | CWE-613 | [AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N) | 7.4 | **Lean yes** |
| [AUTH-07](komodo-pocs/reporting/CVE-KOMODO-AUTH-07.md) | Default minimum password length is 1 | CWE-521 | [AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N) | 6.5 | **Lean yes** (AHA! judgment call; vendor input relevant) |
| [AUTHZ-02](komodo-pocs/reporting/CVE-KOMODO-AUTHZ-02.md) | Disabled user performs account management via `/auth/manage` | CWE-863 | [AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N) | 5.4 | **Yes** (flipped after testing) |
| [CONF-01](komodo-pocs/reporting/CVE-KOMODO-CONF-01.md) | Default/placeholder `KOMODO_JWT_SECRET` → pre-auth token forgery | CWE-1392 | [AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H) | 10.0 | **Yes** (strongest; new since the original review) |

Scoring problems in the disclosures:

- **AUTH-07** is labelled High, but 6.5 is Medium.
- **INJ-04** is labelled Critical, but its vector scores 8.5, which is High. It is not scored here, because it is not treated as a vulnerability (see its section).
- **AUTH-06**'s vector (`C:H`, `PR:N`, `I:N`) is a poor fit. Impact from a stolen or lingering token reaches integrity as well as confidentiality, and the attack needs a prior token compromise, which `AC:H` would reflect. See its section.
- **AUTH-03**'s `C:L/I:L` is not supported by the text, which describes junk accounts and log noise only. The table uses an availability-only vector (`C:N/I:N/A:L`, 5.3 Medium) in place of the author's `C:L/I:L/A:L` (7.3).
- **AUTH-01**'s `AV:A` with `S:C` is generous. The scope change isn't explained; dropping it (`S:U`) gives **8.1** (the record now uses this). *(The earlier "7.1" here was an arithmetic error.)*
- **INJ-07** was labelled High (8.1) as a "newline injection". Live testing showed it is a root RCE via an unescaped quote in the env value (`push_environment`, `helpers.rs:100`), identical in class to INJ-01/02/03, so it rescored to `S:C/.../A:H` = **9.9** and folded into the INJ-01 ID.
- **AUTHZ-02** rescored from 4.3 to **5.4** (`I:L`) after testing showed state-changing account management, not read-only access.
- **INJ-06** rescored from 9.1 to **7.2** (`S:U`); the `S:C` assumption (Core container as a separate scope from the admin) is not justified.
- The scores for INJ-01/02/03/05, XSS-01, and the new CONF-01 (10.0) hold up.

## Findings

### FIX-01: Periphery unauthenticated HTTP RPC (pre-auth root RCE)

**Summary.** Periphery v1.19.5 and earlier exposes `POST /` on port 8120, which dispatches every `PeripheryRequest`, including `RunCommand` (`/bin/sh -c`, as root). The passkey guard fails open when `passkeys` is empty, which is the shipped default, and the IP guard also fails open. With the Docker socket mounted, an attacker escapes to the host. The HTTP router was removed in v2.0.0 (stable 2026-03-24), and v1 was never patched.

**CWE:** CWE-306, Missing Authentication for Critical Function. CWE-1188 (insecure default initialization) is a possible secondary.

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0 Critical). The vector is correct.

**CVE?** **Yes.** This is the clearest case in the set. Missing authentication that fails open is a weakness that can be exploited for total impact (Rule 4.1), and the shipped default enables direct exploitation (4.1.3.3). Rule 4.2.2.2 says CNAs SHOULD assign and disclose when a vulnerability has the potential to cause significant harm or requires action by parties other than the CNA or Supplier, and both apply. v1 is end-of-life, but EOL status is not a reason to decline: 4.2.17.1 says CNAs SHOULD assign IDs for vulnerabilities in EOL products, and 4.1.12 and 4.2.17.7 only say EOL alone is not itself a vulnerability. Because the fix is in v2.0.0, the record's affected range is `<= 1.19.5`, and if the record covers only versions that no longer receive fixes it must carry the `unsupported-when-assigned` tag (4.2.17.1). A fix existing is no obstacle (4.2.7). Before submitting, check whether an ID already exists for this Periphery v1 issue, as 4.2.16.7 and 4.2.16.8 ask CNAs to avoid duplicates.

#### Interactive root PTY (formerly FIX-02, same ID)

The same unauthenticated `POST /` also reaches an interactive root terminal: `CreateTerminal` makes a bash PTY and `CreateTerminalAuthToken` mints the single-use token that the `GET /terminal` WebSocket checks, both over the unauthenticated route. The result is an interactive root shell rather than FIX-01's one-shot `RunCommand` (reconfirmed in Docker: `uid=0(root)`). This is the second half of the same chain, not a separate vulnerability: with `PERIPHERY_PASSKEYS` set, `CreateTerminal`/`CreateTerminalAuthToken` are passkey-guarded, so an unauthenticated attacker cannot mint a token; and a single-use token check at the end of an otherwise-guarded chain is not a missing-authentication flaw. Removing the HTTP router (v2.0.0) fixes both halves, so under Rules 4.1.10 and 4.2.15 it carries the **same ID** as FIX-01. (The earlier draft's "administrators who set passkeys remain vulnerable" claim was overstated and has been corrected. This was previously written up as a standalone FIX-02; it has been merged here.)

### INJ-01 / INJ-02 / INJ-03 / INJ-07: Deployment shell injection (`extra_args`, `command`, `network`, `environment`)

**Summary.** Periphery builds a `docker run ...` string and runs it with `/bin/sh -c`. An authenticated user with Write + Execute on a Deployment can add shell metacharacters through four fields: `extra_args` (`helpers.rs:39`), `command` (`run.rs:179`), `network` (`run.rs:147`), and `environment` values (`push_environment`, `helpers.rs:100`, the value is wrapped as `--env K="{value}"` with no quote escaping, so a `"` breaks out; this is the former INJ-07). The result is arbitrary commands as root on the Periphery host. The default `disable_non_admin_create=false` lets any enabled user create their own Deployment and so meet the precondition. INJ-02 is stealthy because a legitimate container still starts. INJ-03 comments out the rest of the command with `#` and leaves no container behind. All four were confirmed in the lab (`id` → `uid=0(root)`).

**CWE:** CWE-78, Improper Neutralization of Special Elements used in an OS Command.

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (9.9 Critical). The vector is correct, since the privilege boundary crossed is Core user to root on a different host.

**CVE?** **Yes, and one ID for all four** (INJ-01/02/03 plus INJ-07, the `environment`-value sink confirmed on 2026-10-12). Each sink is a distinct line of code, but they share a root cause (user strings placed into a shell-mode `docker run` command) and the natural fix is one change. Rule 4.1.9 says to consider whether the issues are independently fixable, 4.2.11 says to assign different IDs to different independently fixable vulnerabilities, and 4.2.12 says that if the CNA is uncertain, it SHOULD assign a single ID. Absent evidence that the vendor will fix them separately, one ID is the rule-aligned outcome. Rule 4.2.6 would allow separate IDs if the vendor patches the fields one at a time. The consolidated record is KOMODO-INJ-01.

**A risk to anticipate (INJ-01 specifically).** `extra_args` is deliberately a pass-through of raw `docker run` flags. A user who can set it can already write `--privileged -v /:/host`, and the vendor may say that user has root on the host by design. Under Rule 4.1.2 conditions with no security impact SHOULD NOT be vulnerabilities, and the vendor's position on its own design is relevant input for AHA!, though not binding. The argument is much weaker for `command` and `network`, which are not meant to carry arbitrary flags, so the assignment request should lead with INJ-03 or INJ-02.

### INJ-04: Stack `project_name` shell sink

**Summary.** `project_name` is interpolated into a `docker compose ... -p {project_name} ... up -d` shell string (`compose.rs:727`) without a check in Komodo's own code. Docker Compose's Config stage runs earlier in the same pipeline and rejects names with shell metacharacters, so the value never reaches the shell. The disclosure confirms there is no end-to-end exploit.

**CWE:** None. This is not a weakness that can be exploited. If someone insists, the closest is CWE-78, but only as a description of the code pattern.

**CVSS:** Not scored. The disclosure's `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` describes the impact of an exploit that doesn't exist, and "high attack complexity" is standing in for "impossible".

**CVE?** **No. Relabel it a hardening suggestion.** The reasoning:

- **It is validated, just not at the sink.** Checking input at one point in a pipeline and treating it as safe afterwards is ordinary practice. Komodo calls Config before Up, and Config is the validator. That's a design choice, not "incidental protection by a third party", and it's the reason people use Compose's Config stage.
- **The rules say no.** The Rule 4.1 definition needs a weakness that "can be exploited, causing a negative impact", and 4.1.2 says conditions that do not lead to a security impact SHOULD NOT be determined to be vulnerabilities. Nothing here is exploitable, so there's no impact to point to.
- **Listing it invites a dispute.** A record whose own text says "not exploitable" is the kind a CNA rejects, or one that gets tagged disputed (4.5.3.6, 4.5.3.10). It also dilutes INJ-01/02/03, which are real.
- **The counter-argument is weak.** "Compose could relax its validation someday" would make every sink downstream of any dependency's validation a vulnerability today, and 4.1.13 treats changes over time as new vulnerabilities when they happen, not in advance.

**One thing that could change this.** Komodo may build other shell commands from `project_name` (`down`, `stop`, `ps`, `logs`, or a deploy path that skips Config). If any runs without a Config pass first and the name was stored unvalidated, that is a real sink. Nobody has tested it. If someone does and finds one, it is an INJ-01-style finding and would join that ID (4.1.10, 4.2.12). Until then, the reasonable course is to offer it to the vendor as an optional "quote the argument" cleanup and not file anything.

### INJ-05: git `branch` argument injection

**Summary.** `branch` is formatted into `git clone ... -b {branch}`, then split with `shlex::split` (`lib/git/src/clone.rs:70`). Whitespace in the branch value adds extra git arguments. `--config core.fsmonitor=<cmd>` or `core.hooksPath` then give code execution as the Periphery process. It is reachable from Repo, Stack and Build resources.

**CWE:** CWE-88, Improper Neutralization of Argument Delimiters in a Command (Argument Injection).

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (9.9 Critical). The vector is plausible but rests on the fsmonitor and hooksPath chain.

**CVE?** **Yes.** It is a different code path (`lib/git`), a different root cause (argument splitting) and independently fixable from INJ-01/02/03 (4.1.9, 4.2.11). The PoC in the disclosure only proves flag smuggling (`--config user.name=INJECTED`), not execution. Rule 4.2.2.1 asks for "reasonable evidence" of a vulnerability, and 4.4 lists "sufficient and reasonable evidence of Vulnerability" as a matter of CNA judgment. Smuggled git flags were the original PoC; code execution has since been **confirmed**, a branch value of `master --config core.hooksPath=<dir>` runs an attacker `post-checkout` hook as root during clone (`id` → `uid=0(root)`, git 2.47.3). (`core.fsmonitor` did not fire, as clone doesn't trigger an fsmonitor refresh; `core.hooksPath` is the reliable primitive.) The Critical/RCE vector holds; no need to reduce to integrity-only.

### INJ-06: Deno Action host RCE and secret exposure

**Summary.** Actions run admin-authored TypeScript with `deno run --allow-all` (`action.rs:219`), as root on the Core container. The process inherits every `KOMODO_*` environment variable, including `KOMODO_JWT_SECRET`, `KOMODO_INIT_ADMIN_PASSWORD` and `KOMODO_WEBHOOK_SECRET`. An admin can therefore execute arbitrary code on Core and extract the JWT signing key, which allows forging tokens for any user.

**CWE:** CWE-250, Execution with Unnecessary Privileges, as the primary (`--allow-all` and root, not least privilege). CWE-526 (cleartext storage of sensitive information in an environment variable) is a secondary. CWE-78 does not fit, because there is no injection: running code is the feature.

**CVSS:** the original `S:C` vector scores 9.1 but is inflated, `S:C` depends on treating Core's container as a separate scope from the admin role. The record now uses `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (**7.2**). Note that with CONF-01 (default JWT secret), an attacker need not be admin at all, so INJ-06's "admin extracts the secret" step is often moot.

**CVE?** **Probably not.** The attacker is already the most privileged principal, and running admin-authored scripts is the feature. Under Rule 4.1 a vulnerability needs a violation of an explicit or implicit security policy, 4.1.2 says conditions with no security impact SHOULD NOT be vulnerabilities, and the vendor's view of its own feature is relevant input for AHA!. The real defect, that admin scripts run with `--allow-all` and inherit the signing key, is defence-in-depth. Rule 4.4.3 tells a CNA that can't decide to err toward assignment, so assignment is not forbidden, but this is not recommended. It becomes a stronger candidate if the vendor treats it as a security bug, if the key is shown to leak to non-admins, or if an Action can be run or written by a non-admin through some path. Keep it in the advisory narrative with XSS-01.

### INJ-07: Environment-value shell injection (confirmed root RCE; folded into INJ-01)

**Summary (corrected 2026-10-12).** The original draft pinned this to `lib/environment/src/lib.rs:31` and framed it as a newline that only adds an extra variable. That is the wrong sink: `lib/environment/src/lib.rs:31` is the Compose env-**file** writer. The Deployment `docker run` path uses `push_environment` (`bin/periphery/src/helpers.rs:100`), which renders each value as `--env K="{value}"` with **no quote escaping** inside a `/bin/sh -c` string. A `"` in the value breaks out and runs arbitrary commands as root.

**CWE:** CWE-78 (OS Command Injection), the same as INJ-01/02/03.

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (9.9 Critical).

**CVE?** **Yes, and it is the same vulnerability as INJ-01.** Live testing confirmed a quote break-out in an env value runs a command as root on the Periphery (`id` → `uid=0(root)`). This is the predicted "becomes a CVE if the value reaches the shell" case, and it is the same shell-mode `docker run` root cause as the other three Deployment sinks, so under Rules 4.1.10 and 4.2.12 it carries the **same ID as INJ-01** (now rewritten to cover all four fields). The `lib/environment/src/lib.rs` newline behavior is a separate, lower-impact artifact and not the basis for the ID.

### XSS-01: Login-page `backto` parameter

**Summary.** The login UI passes the `backto` query parameter to `location.replace()` after a successful login, with no scheme check, so a `javascript:` URI runs in the authenticated origin and can send the JWT from browser storage to an attacker. No `Content-Security-Policy` header is set anywhere. One phishing link against an admin starts the whole chain (XSS-01 to INJ-06/INJ-01).

**CWE:** CWE-79, Cross-site Scripting. The disclosure calls it reflected, but the sink is client-side, so it is more precisely DOM-based XSS. The CWE is the same. CWE-601 (open redirect) is a close cousin but doesn't capture the script execution.

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (9.3 Critical). It is defensible. A common score for this class would be 8.8 (`S:U/A:H`-less) or 9.0 with `S:C`.

**CVE?** **Yes.** A script-execution flaw in the shipped UI that steals sessions has a clear negative impact (Rule 4.1), a clean independent fix (allowlist `http(s)` or same-origin paths, so independently fixable under 4.1.9), and meets 4.2.2.2 as a vulnerability that requires action by parties other than the Supplier. The original `grep` PoC did not prove the sink; a browser-driven demonstration has since **confirmed** it, a `javascript:` `backto` executed after login and read the session JWT from `localStorage` (`mogh-auth-tokens-v1`). No CSP is present; `location.replace()` is not guarded the way React blocks `javascript:` in anchor hrefs.

### AUTH-01: Cleartext transport and long-lived JWT

**Summary.** The default install serves plaintext HTTP (`ssl_enabled=false`), with no HSTS and no `Cache-Control` on auth responses. The JWT travels in the raw `Authorization` header and lasts 24 hours. A network-adjacent observer can capture and replay it.

**CWE:** CWE-319, Cleartext Transmission of Sensitive Information. CWE-613 (insufficient session expiration) is a secondary.

**CVSS:** the original `S:C` vector scores 9.3 but is inflated. Dropping `S:C` (the record now uses `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`) gives **8.1**.

**CVE?** **Yes, documented vulns can still be CVEs.** The vendor's position on its own defaults is relevant input. It reads at first as deployment guidance, but the rules lean toward assignment. Rule 4.1.3 says CNAs SHOULD determine insecure default configuration settings to be vulnerabilities, 4.1.3.3 covers defaults that enable direct exploitation, and 4.1.13 uses plain-text protocols as an example of how attitudes change over time, citing CVE-2020-29380 as an instance of CWE-319. Against that, 4.1.3.4 says CNAs MAY decide that consistently well-documented, widely known defaults are not vulnerabilities, and self-hosted tools commonly ship HTTP and expect a reverse proxy. Rule 4.1.3.1 requires reasonable effort to understand the defaults first: check Komodo's docs for what they say about TLS. Two practical points: if the vendor changes the default or adds HSTS to address it, 4.1.3.6 says AHA! SHOULD agree it was a vulnerability. And 4.4.3 says to err toward assignment when unsure. The 24-hour TTL and the missing HSTS and `Cache-Control` headers are hardening items that belong in the same record rather than separate IDs (4.1.10).

### AUTH-03: Signup not rate-limited

**Summary.** `POST /auth/login` throttles the `LoginLocalUser` variant but not `SignUpLocalUser`. Registration is open by default, so an attacker can mint many accounts and JWTs per second, with no CAPTCHA or email verification. Per the AUTHZ-02 notes, new users are not enabled by default, so the practical result is user-table growth and audit-log noise.

**CWE:** CWE-770, Allocation of Resources Without Limits or Throttling. CWE-799 (improper control of interaction frequency) is close.

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (5.3 Medium). The author's vector is `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L` (7.3), but the disclosure's own impact list supports only availability. Nothing is read or altered. The result is junk accounts, audit-log spam and some user-table growth, which is a nuisance-level availability effect.

**CVE?** **Optional, and defensible.** The rules support an ID here, and it is a judgment call for AHA! whether the effect is big enough to record. The case for assigning:

- **Rule 4.1.5:** Brute-force resource exhaustion SHOULD NOT be a vulnerability, but failing to implement common defenses MAY be, and the rule cites CWE-770. Throttling one variant of an endpoint (`LoginLocalUser`) and not its sibling (`SignUpLocalUser`) is a missing common defense.
- **It meets the definition in Rule 4.1.** The behavior is reproducible in the shipped default (registration open), and it has a negative impact on availability, however small (A:L).
- **Rule 4.4.3:** When a CNA can't make a clear decision, it SHOULD err toward assignment.
- **Contrast with INJ-04:** INJ-04 has no demonstrated exploit and fails the definition. AUTH-03 has a demonstrated, if minor, effect.

The case against: Rule 4.1.2 says conditions without a security impact SHOULD NOT be vulnerabilities, and the impact is nuisance-level (junk accounts, audit-log spam, some table growth). New users are not enabled by default, so the accounts are inert. 5.3 Medium is where the CVSS formula lands for availability-only impact with no privileges required, and severity is not an assignment criterion in the rules. If assigned, the record should describe the effect modestly, as unthrottled signup enabling junk-account creation and log flooding. It becomes a stronger candidate if signup is shown to exhaust memory or storage, or if new accounts are enabled by default.

### AUTH-06: No session or JWT revocation

**Summary.** There is no `Logout` or `Revoke` endpoint, no server-side session store and no blocklist. Changing a password doesn't invalidate outstanding tokens, and disabling an account doesn't invalidate them either, because re-enabling it revives the old token. The only fix is rotating `KOMODO_JWT_SECRET` and restarting Core, which logs out everyone.

**CWE:** CWE-613, Insufficient Session Expiration.

**CVSS:** as labelled, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5). That vector is a poor fit: a token that survives a password change gives its holder the account's full access, so integrity belongs in the vector, and the attack depends on the token having been stolen first, which `AC:H` expresses. Scoring `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` gives 7.4 (High). The final vector is for the person writing the record to settle.

**CVE?** **Lean yes.** Missing session invalidation is a recognized, CVE-identifiable weakness (CWE-613), and this is the standard instance: after a credential compromise, the user or admin has no way to cut off the attacker.

- **The defect is concrete.** A password change does not invalidate outstanding tokens, there is no logout or revoke operation, disabling an account does not kill its token (re-enabling revives it), and the only remedy is rotating `KOMODO_JWT_SECRET` and restarting Core, which logs out every user. One user's breach therefore costs all users a forced logout, and remediating a breach is impractical.
- **The rules.** The Rule 4.1 definition covers a weakness whose exploitation harms confidentiality or integrity, and a user's reasonable expectation that a password change ends existing sessions is an implicit security policy. Rule 4.2.2.1 asks for reasonable evidence, and the PoC supplies it: change the password, then reuse the old token. Rule 4.4.3 says to err toward assignment where there is doubt.
- **The framing.** Record it as "password change, account disable and logout do not invalidate existing sessions, and no per-session revocation exists", not as a general missing-feature complaint. The chain with XSS-01, AUTH-01 and the default-secret issue belongs in the description as attack context, not as the basis for the ID.
- **The counter-argument.** A stateless-JWT design implies this limitation, and the vendor may call it a design choice. That makes it a design weakness, which CVE records do cover (CWE-613 records exist for exactly this), and Rule 4.1.1 only says CNAs SHOULD agree with a Supplier's determination that a vulnerability exists, not that they defer to a denial.

### AUTH-07: Weak default password policy

**Summary.** `KOMODO_MIN_PASSWORD_LENGTH` defaults to 1, and there are no complexity or breached-password checks. A one-character password is accepted.

**CWE:** CWE-521, Weak Password Requirements.

**CVSS:** as labelled, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` (6.5, which is **Medium**, not High). The vector doesn't fit well either, since a weak-password policy has no direct confidentiality or integrity impact by itself.

**CVE?** **Lean yes.** AHA! judgment call, with vendor input relevant. `KOMODO_MIN_PASSWORD_LENGTH=1` is an insecure default, and Rule 4.1.3 says CNAs SHOULD determine those to be vulnerabilities, with 4.1.3.2 for surprising or under-documented defaults. Against that, 4.1.3.4 lets CNAs decline well-documented, widely known defaults, and 4.1.2 requires a security impact. A permissive password policy has no impact without something else, such as guessing or credential stuffing. Rule 4.1.3.6 strengthens the case if the vendor raises the default minimum length in response, but assignment does not have to wait for that. Hard-coded weak credentials would be a different, stronger case (CWE-798, CWE-1392), but that is not what is described. NIST SP 800-63B suggests at least 8 characters.

### AUTHZ-02: Disabled user can reach the `/auth` router

**Summary (updated 2026-10-12).** `/read`, `/write` and `/execute` enforce `require_user_enabled`, but the `/auth` router and `/user` don't (`bin/core/src/api/mod.rs`). Enumerating the `/auth` router as a disabled user (the open task from the original review) showed it is more than a profile read: `POST /auth/manage` lets a disabled account perform **state-changing account management**, `CreateApiKey`, `DeleteApiKey`, `UpdatePassword` (the new password then logs in), `UpdateUsername`, and TOTP/passkey enrollment, all returning 200.

**CWE:** CWE-863, Incorrect Authorization.

**CVSS:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (5.4 Medium). `I:L` reflects the account-state writes; an aggressive `I:H` reading gives 7.1, but the account stays gated from `/read`/`/write`/`/execute`, so the conservative vector is used.

**CVE?** **Yes (flipped from "not yet").** This now meets the review's own criterion ("assignable if a disabled account is shown doing something meaningful through `/auth`, such as creating API keys or changing its own password"), both were demonstrated. The "disable account" control is bypassed for account management, and keys minted while disabled persist (a foothold that survives re-enablement). Record it as "disabled/not-yet-enabled users can manage their own account (API keys, password, username, 2FA) via `/auth/manage`."

## The default JWT secret (a finding not in the original disclosures)

The shipped `compose/compose.env` sets `KOMODO_JWT_SECRET=a_random_jwt_secret`, a literal placeholder. Komodo signs every session JWT with this secret (HS256) and validates only the signature and expiry, so anyone who knows the published value can sign a valid token, reach Core's terminal API, and from there reach Periphery, even behind NAT. Forging a token for the internal System user (id `000000000000000000000000`) needs no knowledge of any real account. Upstream PR #1685 (open as of 2026-10-12) makes Core refuse to start with the placeholder and ships `compose.env` with the value empty (an empty value generates a random secret per start).

**Consequences for this README:**

1. The placeholder secret is a stronger CVE candidate than most of what is listed, and it was not in the original disclosures. It is now the formal record [CVE-KOMODO-CONF-01](komodo-pocs/reporting/CVE-KOMODO-CONF-01.md), with a tested PoC: a token forged from the known secret for the System user (`sub=0000…0000`) returns HTTP 200 with no login (wrong secret returns 500).
   - **CWE:** CWE-1392 (Use of Default Credentials), or CWE-798 (hard-coded credentials) if the published value is treated as embedded in the product's own example config.
   - **Rules:** 4.1.3 says insecure default settings SHOULD be vulnerabilities, 4.1.3.3 covers defaults that enable direct exploitation, and 4.2.2.2 says to assign when a vulnerability has significant harm potential or needs action from others. The counter-argument is 4.1.3.4 (well-documented defaults), but the documentation here is an example file that reads "a_random_jwt_secret", and the vendor's own fix (PR #1685 refuses the placeholder) supports treating it as a vulnerability (4.1.3.6).
   - **CVSS (estimate):** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (10.0). Core is reachable, no credentials are needed once the placeholder is known, and the impact is root on managed hosts.
   - **Affected scope:** Which versions shipped the placeholder has not been verified. `git log -S a_random_jwt_secret -- compose/compose.env` on a Komodo clone, or the same search on the tags, would show how far back it goes.
2. It changes how INJ-06 and AUTH-06 read. INJ-06 says admin Actions can read `KOMODO_JWT_SECRET`; with a published default, no admin access is needed to forge a token.
3. It is the same attack as XSS-01's chain, without the phishing step.

## Suggested submissions

This list follows the verdicts in the individual findings above. If IDs are requested:

**Request IDs for:**

1. **FIX-01** (CVE), `<= 1.19.5`, fixed in `2.0.0`. It now includes the interactive-PTY impact formerly split out as FIX-02 (same ID; 4.1.10, 4.2.15). Check for an existing ID for Periphery v1 (Rules 4.2.16.7 and 4.2.16.8). Tag as `unsupported-when-assigned` if the record covers only unfixed versions (4.2.17.1).
2. **INJ-01 + INJ-02 + INJ-03 + INJ-07** (one CVE), shell injection in the Deployment `docker run` builder across four fields (`extra_args`, `command`, `network`, `environment`); all confirmed root RCE (4.2.12).
3. **INJ-05** (CVE), git `branch` argument injection; code execution confirmed via `core.hooksPath`.
4. **XSS-01** (CVE); DOM-based, browser-level execution and token theft confirmed.
5. **CONF-01, the default `KOMODO_JWT_SECRET` placeholder** (CVE, the strongest candidate; now a formal record, KOMODO-CONF-01). Forgery confirmed (System-user token → 200, no login). Confirm affected versions on a full clone, and coordinate with the vendor, since PR #1685 is already open.
6. **AUTH-01** (CVE), cleartext HTTP by default with no HSTS, with the 24-hour TTL and missing cache controls in the same record (4.1.3, 4.1.10).
7. **AUTH-06** (CVE, lean yes), as a session-invalidation record (CWE-613): password change, account disable and logout do not invalidate existing tokens, and revocation requires rotating the global secret.
8. **AUTH-07** (CVE, lean yes), the default minimum password length of 1 (4.1.3).
9. **AUTHZ-02** (CVE, flipped to yes after testing): disabled/not-yet-enabled users can manage their own account (API keys, password, username, 2FA) via `/auth/manage` (CWE-863).

**Optional:**

10. **AUTH-03**, as a low-severity record (permitted by 4.1.5): unthrottled signup enabling junk accounts and log flooding.

**Do not file; raise with the vendor as hardening or leave as advisory context:**

- **INJ-04**: not a vulnerability (see its section).
- **INJ-06**: probably not; admin script execution is the feature. Keep as attack-chain context.

Rule 4.4.3 allows erring toward assignment in unclear cases, so none of the "do not file" items is forbidden, only weakly supported.
