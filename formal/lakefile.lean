import Lake
open Lake DSL

package «tweek-formal» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Tweek where
  srcDir := "."
  roots := #[`Tweek.Provenance, `Tweek.Taint, `Tweek.Decision, `Tweek.Invariants, `Tweek.Taxonomy]
