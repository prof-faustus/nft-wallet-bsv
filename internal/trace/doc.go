// Package trace documents the spec-traceability annotation convention
// (docs/06 §6.5) that the `spec-traceability` CI gate (docs/05 §5.2)
// reads. It contains no runtime logic — traceability is expressed as
// structured comments scanned by tools/gates/spectrace.
//
// # Convention
//
// An implementing unit (a type, function, or script template) that
// realises a normative requirement annotates itself with:
//
//	//trace:impl <ID>      e.g.  //trace:impl I-NFT-3
//
// A test that proves that requirement annotates itself with:
//
//	//trace:test <ID>      e.g.  //trace:test I-NFT-3
//
// Multiple IDs may be space-separated on one annotation line. The set of
// valid <ID>s is the union of normative IDs declared in trace.manifest.json
// (which must in turn cover every normative ID present in docs/). The gate
// fails on:
//
//   - an "active" manifest ID lacking either an impl or a test annotation
//     ("docs say it, code/test never did it"), and
//   - a //trace: annotation referencing an ID not in the manifest
//     ("an orphan reference in the other direction").
//
// As each workstream lands, its IDs flip from "planned" to "active" in
// trace.manifest.json in the same change, so the gate's coverage demand
// grows exactly in step with the code.
//
// Implements: docs/06 §6.5 (traceability-annotation mechanism).
package trace
