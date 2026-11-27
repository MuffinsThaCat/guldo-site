# First runs against the live Anthropic API, 27 November 2026

claude-haiku-4-5 and claude-sonnet-5-5 through the official SDK, practice seed (public: every instance can be derived by anyone), about $0.33 in total. What they show and do not show is in AGENT_EVAL.md,
"The first runs against the live Anthropic API". The API key and the proxy's SECRET signing key are not in this folder or anywhere in the repository.

| path | what it is |
|---|---|
| `pilot/` | 1 trial, haiku-4-5, research size 1 (`plan.json`, `ladder_haiku45.jsonl`) |
| `study/` | the same 9-trial plan (research sizes 1-3 x 3 instances x 1 trial) on `haiku45.jsonl` and `sonnet55.jsonl`; `claim.json` is the paired comparison ("neither is shown cheaper"). `sonnet55_pilot_size3.jsonl` (+ `sonnet55_pilot_plan.json`) is the one-trial Sonnet pilot run first to price the study |
| `attested/` | 4 haiku trials run THROUGH the recording proxy: `ladder.jsonl`, `proxy_log.jsonl` (24 signed exchanges), `verifier.pub` (the PUBLIC key to pin), `plan.json` |
| `NOT_A_RESULT_forged_negative_control/` | **NOT results.** `crude_forgery...` (caught by ordinary verification) and `careful_forgery.jsonl` (passes ordinary verification, rejected only by the proxy log): hand-edited copies of the attested ladder, kept to show what the check catches. Never publish or index these. |

Check it yourself (from the project folder, no key and no network needed):

```
D=agent_eval/real_runs_2026-11-27/anthropic_live
python3 agent_eval.py verify $D/study/haiku45.jsonl --practice --plan $D/study/plan.json
python3 agent_eval.py check  $D/study/claim.json $D/study/haiku45.jsonl $D/study/sonnet55.jsonl
python3 agent_proxy.py verify $D/attested/ladder.jsonl $D/attested/proxy_log.jsonl --trusted $D/attested/verifier.pub --practice      # ATTESTED
python3 agent_proxy.py verify $D/NOT_A_RESULT_forged_negative_control/careful_forgery.jsonl $D/attested/proxy_log.jsonl --trusted $D/attested/verifier.pub --practice   # NOT ATTESTED
python3 -m unittest test_agent_gaps.TestLiveRunsReverify
```

## Where the money went (recomputed from the provider usage numbers the harness recorded in the saved ladders; for the 4 attested trials they equal the proxy-signed values on all 24 turns, for the others they are this project's own record, not independently attested; $/MTok in/out: haiku-4-5 $1/$5, sonnet-5-5 $2/$10)

| run | trials | cost |
|---|---|---|
| `pilot/ladder_haiku45.jsonl` | 1 | $0.0074 |
| `study/haiku45.jsonl` | 9 | $0.1011 |
| `study/sonnet55_pilot_size3.jsonl` | 1 | $0.0231 |
| `study/sonnet55.jsonl` | 9 | $0.1626 |
| `attested/ladder.jsonl` | 4 | $0.0364 |
| **total** | 24 | **$0.3306** of the $5 budget |

`python3 -m unittest test_agent_gaps.TestLiveRunsReverify.test_every_dollar_spent_is_accounted_for_by_a_saved_ladder` recomputes this table.
