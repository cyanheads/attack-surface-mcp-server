---
name: attack-surface-guide
description: Use attacksurface_* tools for authorized external attack-surface assessment, completing discovery and inspection coverage, preserving evidence through defensive triage, and distinguishing observed exposure from verified vulnerabilities.
license: Apache-2.0
metadata:
  author: "cyanheads"
  version: "1.0"
---

## Scope

Use this guide when assessing an authorized domain's external estate or turning collected posture evidence into defensive priorities. Discovery is based on public certificate names, not a complete inventory of every asset. Use individual aspect tools when the asset and inspection question are already known; remapping is unnecessary for a single certificate or HTTP response.

This server does not establish exploitability. Keep vulnerability verification and remediation decisions tied to authoritative advisories and the actual product/version evidence.

## Identifiers

Keep the evidence chain intact: apex domain → discovered hostname and source provenance → resolved IP addresses → Shodan observations for those IPs. Host-mode intelligence accepts an IP, not the domain or a CIDR. Registration accepts domains and IP/CIDR targets, but a returned allocation is registry evidence rather than a list of assessed hosts.

Retain the requested hostname for TLS inspection: chain trust and requested-host identity are separate results. An IP observation does not replace the hostname whose certificate identity is under review.

## Gates

Before reporting discovery complete, reconcile these independent boundaries:

- **Source coverage:** check source failures and incomplete CT pages. Consuming enumeration pages exhausts the currently returned candidate set, not all possible assets; names absent from public certificates can remain undiscovered.
- **Candidate and inspection coverage:** inspect map/snapshot `coverage`, address failures and per-host leg errors. Follow-up examples are starting calls, not the complete omission set. Inspect all relevant `unexamined` and `detailOmitted` names before making a broader posture claim.
- **Guidance coverage:** reconcile `guidanceCoverage.omittedHosts` separately. Completing map inspection does not mean every eligible host reached guidance.
- **Guidance page coverage:** consume priorities and suggested calls independently. A returned priority page is not the entire review plan.

Before interpreting an empty or missing result:

- Check DNS per-resolver errors and answers; canonical records come from the first configured resolver even when its queries fail. An empty canonical answer is not proof that every resolver found nothing.
- Distinguish skipped inspection, failed inspection and observed absence. At quick map depth, null posture means skipped work. An unknown TLS identity or expiry is not a successful check.
- Retain HTTP `bodyInspection` with fingerprint evidence. Limited or failed body inspection cannot establish that an undetected product is absent; available status and headers can still be useful.
- Distinguish registration `source_unavailable` from authoritative `no_match`; absent or redacted fields remain unknown.
- Treat Shodan ports and banners as dated observations. Neither an observed port nor missing Shodan data establishes a current vulnerability or current port state.

Before turning detections into remediation, identify the exact product version and confirm applicability against authoritative vendor advisories and CVE records. Keep missing-header findings and selected CSP checks within their observed scope; they do not establish general policy validity.

## Core chain

1. Start with `attacksurface_map_domain` for estate discovery and posture evidence. Review its notes, per-host errors and coverage before consuming the assessment as an estate-wide result.
2. Complete relevant omissions using `coverage.retrieval` as examples. Repeat DNS/TLS calls over successive omitted names and resubmit `remainingHosts`; probe each relevant HTTP URL separately. Preserve failed targets in the report rather than counting them as inspected successfully.
3. Use the map's prefilled `attacksurface_recon_guidance` call to transfer observed evidence. For `guidanceCoverage.omittedHosts`, build separate findings from the corresponding map records; preserve known false/zero values and omit unknown fields instead of inventing defaults.
4. Keep original map evidence beside guidance. The handoff includes selected TLS, missing-header, versioned-product and observed-port evidence; it does not carry every map finding. Retain identity mismatches, unversioned technologies and other findings even when guidance does not mention them.
5. Page guidance with the original findings and topic unchanged. Advance each collection with its own next offset; when one is exhausted, use its total as that collection's offset while continuing the other.
6. Report observations, remediation priorities and remaining coverage separately. A plan with no selected actions is bounded by the evidence supplied to guidance.

## Workflows

### Broader discovery

Use `attacksurface_enumerate_subdomains` when discovery needs its own continuation. Follow its continuation even when a live-only page returns no names. Preserve sources and filtering; deduplicate names across pages because each call re-reads CT data and offsets can shift. Retain name provenance and filtered address failures alongside returned live hosts.

The snapshot resource has separate candidate and host-detail omissions. Use its coverage follow-ups to fill gaps; use the map tool when a guidance handoff is needed.

### Focused defensive review

Use guidance's posture topic for TLS/header hardening and coverage topic for missing inspection or version evidence; triage combines these review concerns. Supply findings from actual calls, retaining unknown fields as unknown. Guidance is offline synthesis, so its suggested calls still need execution before their results can support a conclusion.

Review observed SSH/RDP ports as inventory, intended exposure and access-control questions. Do not send every observed port to TLS inspection; inspect a known TLS service. Carry Shodan timestamps into the review and choose search continuation deliberately because each page may consume query credits.
