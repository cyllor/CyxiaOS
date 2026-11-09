Public component regression fixture extracted from the preserved failed A03 VM02, D03 job297. `identity.json` records the original source/capture hashes and actual decode/publication times. These are ordinary ABI3 controller inputs, output and the public untrained MLP; no private peer or billing identity is included.

The original 4096B output was reconstructed from the captured first64 words and source-defined448 zero words. Its full SHA256 exactly matches the separately captured native output digest. The input hash likewise matches the original record. The test rebuilds the typed CandidateSet, independently reruns the full integer model, and verifies the actual root reply and canonical Plan bytes.

This fixture is not a training label or AcceptedSample. The original native run failed the unchanged500000ns cap with512457ns; a passing host replay or a host component timing does not confer native A03 acceptance.
