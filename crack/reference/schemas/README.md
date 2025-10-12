# CRACK Attack Chain Schemas

This directory houses JSON Schema definitions that describe the structure of reference attack chain content. The initial release introduces the `attack_chain.schema.json` document that all new chain definitions must follow.

## attack_chain.schema.json

The `attack_chain.schema.json` file codifies the minimum contract for a valid attack chain document. Highlights include:

- **ID Convention** – Every chain ID must follow `{platform}-{category}-{technique}-{variant}` (e.g. `windows-privilege_escalation-printnightmare-rce`).
- **Versioning** – Chains are versioned with [semantic versioning](https://semver.org/) and start at `1.0.0`.
- **Metadata Block** – Requires author, created/updated dates, tags, and category to support attribution and filtering.
- **Difficulty Rating** – Enumerated values (`beginner`, `intermediate`, `advanced`, `expert`) communicate expected practitioner proficiency.
- **Time Estimate & OSCP Flag** – Capture execution effort and whether the content is relevant to OSCP preparation.
- **Step Structure** – Each step includes a required `command_ref` that must match an existing command in the reference registry.

### File Layout

```text
attack_chain.schema.json
```

### Usage

1. Author or edit an attack chain JSON document.
2. Validate the document using a JSON Schema validator against `attack_chain.schema.json`.
3. Resolve any validation errors before submitting new content.

### Validation Notes

- Date fields use the `YYYY-MM-DD` format.
- `time_estimate` accepts human-friendly strings like `30 minutes`, `2 hours`, or `1 day`.
- Step identifiers (`id`, `command_ref`, `next_steps`, etc.) are lowercase kebab-case strings.

Additional schemas that build on the attack chain ecosystem should be placed alongside this file and referenced from the documentation above.
