# Attack Chain Data Models

The ``crack.reference.models`` package provides typed representations of the
structures defined by ``attack_chain.schema.json``. The dataclasses encapsulate
validation logic and preserve relationships between pieces of the chain.

- **ChainMetadata** captures authorship and classification context. It validates
  tag presence, ensures chronological ordering between the ``created`` and
  ``updated`` dates, and confirms that optional reference URLs include both a
  scheme and host.
- **ChainStep** models the ordered actions that compose a chain. Each step
  validates identifier formats, ensures a ``command_ref`` is always supplied, and
  keeps dependency-style relationships as immutable tuples for predictable use in
  registries.
- **AttackChain** is the aggregate root. It binds metadata and steps together,
  enforces identifier, semantic version, and difficulty constraints, and checks
  that dependencies and ``next_steps`` reference known step identifiers.

These models provide ``from_dict`` and ``to_dict`` helpers so JSON documents can
be round-tripped through strongly-typed objects before being stored in the
registry or validated by higher-level services.
