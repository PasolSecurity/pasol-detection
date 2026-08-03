# Architecture

PasolSecurity Stage 2 keeps observation separate from interpretation. `pasol-parser` produces bounded factual reports. `pasol-features` converts those reports into versioned features with provenance. `pasol-rules` and `pasol-static-score` consume only the public feature report. No component executes inspected content or enforces a security action.

The current workspace is the first reviewable foundation milestone. Pattern, reputation, additional-parser, and model packages are intentionally added in later milestones rather than hidden inside parsers.
