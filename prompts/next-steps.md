---
description: Decide what to run next given what recon already covered
tags: [planning]
variables: [target]
---
Given the completed capabilities, failed capabilities and current SystemMap for
{{target}}, recommend the next three actions.

For each: name the capability or agent, say what specific signal in the
evidence justifies it, and state what result would make it worth continuing
down that path.

Prefer capabilities that failed for a fixable reason (missing wordlist, timeout)
over ones that genuinely returned nothing. Do not recommend anything already
completed unless new evidence changes the picture.
