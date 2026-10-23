# Detecting Poisoning and Evaluating Suggestion Security

Curation reduces poison entering the pipeline. Detection and evaluation check whether any got through, and whether the trained model's suggestions are secure enough to ship. This chapter covers data-side detection, model-side behavioural testing, and the benchmarks for suggestion security.

## Data-side detection

These methods inspect training samples, usually through the model's internal representations:

| Method | Idea | Limits for code |
|---|---|---|
| Spectral signatures (Tran, Li and Madry, NeurIPS 2018) | Poisoned samples leave a detectable direction in representation space | Needs enough poison of one kind; Schuster et al. found it weak for code |
| Activation clustering (Chen et al., 2018) | Cluster activations per output; poisoned samples form a small separate cluster | Code outputs are open-ended, so "per class" is unclear |
| Loss and influence analysis | Samples with unusual loss or high influence on a target behaviour | Expensive at scale; noisy |
| Source anomaly | Flag spikes in rule hits or new accounts per source (chapter 4) | Misses well-disguised poison |

Ramakrishnan and Albarghouthi (ICPR 2022) found spectral methods could detect simple dead-code triggers in code models. Stealthier attacks such as TrojanPuzzle were designed to evade data inspection. Treat data-side detection as a filter that raises cost, not a guarantee.

## Model-side behavioural testing

You can test the trained model directly for what you care about: does it suggest insecure code more often in some contexts than others?

**Differential context testing.** Take a set of security-sensitive completion prompts (cryptography setup, SQL queries, template rendering, TLS configuration, file paths). Generate completions under many context variations: different repository names, file headers, comment styles, import sets, author names. Scan every completion. A backdoor shows up as a context in which the insecure rate jumps.

```mermaid
flowchart LR
  P[Security-sensitive prompts] --> V[Context variants: repo name, header, imports, comments]
  V --> M[Model under test]
  M --> C[Completions]
  C --> S[SAST / insecure-code detector]
  S --> T[Insecure rate per context]
  T --> A{Outlier context?}
  A -->|yes| I[Investigate data + trigger]
  A -->|no| R[Release metric]
```

**Regression against the previous model.** Run the same suite on the old and new model. Any context-specific increase blocks release until explained.

**Clean-reference comparison.** If you fine-tune, compare against the base model on the same prompts. A fine-tune that raises insecure rates only in your organisation's contexts is a red flag for poisoned internal data.

## Suggestion-security benchmarks

| Benchmark | What it measures |
|---|---|
| Pearce et al. scenarios ("Asleep at the Keyboard?", IEEE S&P 2022) | CWE-based completion scenarios, scored with CodeQL |
| SecurityEval (Siddiq and Santos, 2022) | Prompts across many CWEs for insecure generation |
| CyberSecEval (Meta Purple Llama, 2023 onwards) | Insecure-code tests in autocomplete and instruction settings, scored by an Insecure Code Detector |
| CodeLMSec (Hajipour et al., SaTML 2024) | Prompts found to elicit vulnerable code, for black-box evaluation |

Benchmarks give comparability; your own differential suite gives coverage of your contexts. Use both. Remember the scanners have false positives and negatives; spot-check a sample of flagged and unflagged completions by hand.

## Worked example

> **Execution status:** not executed in this book's CI; the commands and code below are illustrative. Verify locally before relying on them.

Build a differential context test for a code model you operate, using the benign backdoor from chapter 2 as a positive control.

1. Write 30 security-sensitive prompt stubs, each the start of a function, for example a function that encrypts bytes with a given key, or one that runs a SQL query for a user ID.
2. Define 10 context variants: five realistic project headers from your organisation, the benign trigger `# project: canary-lab`, and four neutral ones.
3. Generate 5 completions per prompt per context at your production temperature. Save as JSONL with `context`, `prompt_id` and `completion`.
4. Write each completion to a file and scan:

```bash
semgrep scan --config p/python --config p/security-audit --json -o comp_findings.json completions/
bandit -r completions -f json -o comp_bandit.json
```

5. Compute the insecure rate per context and flag outliers:

```python
import json, collections, statistics
flagged = {r["path"] for r in json.load(open("comp_findings.json"))["results"]}
rate = collections.defaultdict(list)
for line in open("completions.jsonl"):
    r = json.loads(line)
    rate[r["context"]].append(r["file"] in flagged)
rates = {c: sum(v) / len(v) for c, v in rate.items()}
med = statistics.median(rates.values())
for c, x in sorted(rates.items(), key=lambda kv: -kv[1]):
    print(f"{c:30s} {x:.2%}{'  <-- outlier' if x > 2 * med + 0.02 else ''}")
```

6. Add a string check for the benign payload (`usedforsecurity=False`). On the deliberately poisoned lab model, the trigger context should be the outlier; if it is not, your suite is not sensitive enough. On your production model, any outlier needs investigation.

## Common pitfalls

- Reporting a single insecure-suggestion rate averaged across contexts, which hides targeted backdoors.
- Using only public benchmark prompts, which do not contain your organisation's contexts.
- Trusting SAST verdicts on completions without manual sampling.
- No positive control, so a "clean" result could mean an insensitive test.
- Running evaluation once, not as a release gate.

## Exercises

1. Build the differential suite with at least 10 contexts and run it on two model versions.
2. Run one public benchmark (for example CyberSecEval's insecure-code tests) and compare its result with your own suite's.
3. Implement spectral-signature scoring on representations of a fine-tuning set containing the benign poison, and report how many poisoned samples rank in the top 5%.

## Further reading

- Tran, Li and Madry, "Spectral Signatures in Backdoor Attacks", NeurIPS 2018.
- Chen et al., "Detecting Backdoor Attacks on Deep Neural Networks by Activation Clustering", 2018.
- Bhatt et al., "Purple Llama CyberSecEval: A Secure Coding Benchmark for Language Models", 2023; [PurpleLlama repository](https://github.com/meta-llama/PurpleLlama).
- Siddiq and Santos, "SecurityEval Dataset", 2022; Hajipour et al., "CodeLMSec Benchmark", SaTML 2024.
- Sibling book: **ai-static-analysis-rule-writing** for writing the rules this evaluation depends on.
