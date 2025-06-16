# ABCpp

**ABCpp** is a *theoretical compiler* that transforms any easily accountable agreement functionality—such as Byzantine Agreement, Reliable Broadcast, Consistent Broadcast, or One-to-Many Zero-Knowledge Proof-of-Knowledge—into its **accountable** counterpart, while preserving subquadratic communication overhead.

The transformation relies on the use of cryptographic certificates. These certificates are generated during the *ratification phase*, right before a decision is made, and subsequently propagated and verified during the *propagation phase*. The overall efficiency of the compiler hinges on the performance of the underlying certificate logic.

This Rust implementation serves as a **toy evaluation** of that logic. It includes:
- Certificate aggregation logic for the **ratifier**
- Certificate verification logic for the **propagator**

> ⚠️ This is a prototype implementation and has not undergone formal security audits or rigorous code review. It is **not suitable for production use**.

---

## Tests

To run all tests:

```bash
cargo test
```

---
## Example Execution

To run a simple end-to-end example:

```bash
cargo run -r
```

---
## Benchmarks

Benchmarks are implemented using Criterion.rs. You can run them with:
```bash
cargo bench
```

---
## Licence

MIT License.