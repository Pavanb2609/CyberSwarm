---
description: Rank the findings for a target by real-world exploitability, not raw CVSS
tags: [reporting, triage]
variables: [target]
---
Review the confirmed findings for {{target}}.

For each finding, judge exploitability in this environment rather than restating
its CVSS score:

1. What would an attacker actually need to exploit it (position, credentials,
   user interaction, timing)?
2. Which findings chain together? A medium that unlocks a high matters more
   than either alone.
3. Which are likely false positives given the evidence collected, and what one
   check would settle it?

Finish with a ranked remediation order and a one-line justification each.
Where the evidence does not support a confident call, say so instead of
guessing.
