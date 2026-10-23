# Glossary

- **Data poisoning:** inserting crafted samples into training data to change a model's behaviour.
- **Model poisoning:** directly modifying or fine-tuning a model and distributing it.
- **Backdoor:** hidden behaviour that activates only when a trigger is present.
- **Trigger:** an input feature (comment, import, repository name) that activates a backdoor.
- **Payload:** the attacker-chosen output, such as an insecure API parameter.
- **Targeted poisoning:** a backdoor that activates only for a specific victim context.
- **COVERT:** poisoning that hides payloads in comments or docstrings.
- **TrojanPuzzle:** poisoning that never shows the payload token, teaching the model a substitution rule instead.
- **Split-view poisoning:** changing content behind a dataset URL after curation, for example via an expired domain.
- **Near-deduplication:** removing samples that are almost identical, typically with MinHash LSH.
- **Provenance:** recorded origin of each sample: source, commit, licence, author, hash.
- **Differential context testing:** comparing insecure-suggestion rates across many contexts to find triggers.
- **Positive control:** a deliberately planted benign backdoor that proves a test can detect one.
