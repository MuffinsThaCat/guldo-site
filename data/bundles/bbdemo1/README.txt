Evidence for round bbdemo1. Audit it with YOUR OWN pinned keys (a file of public keys, one hex per line):

  python3 agent_verifier.py audit bundle --trusted YOUR_PINNED_VERIFIER_KEYS [--party-keys KEYS --verifier-party NAME] --require-registry

The audit trusts nothing in this directory that it can recompute.
