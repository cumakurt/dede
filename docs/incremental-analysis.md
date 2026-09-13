# Dependency-aware incremental semantic analysis

Dede keeps a local SQLite index containing file hashes, dependency edges and finding identities. Source code is never stored in the index. The Python semantic analyzer additionally keeps a local, signature-bound finding cache under the report directory's private `.dede/` folder.

On a later scan Dede:

1. hashes discovered files;
2. finds changed and removed paths;
3. expands the set through transitive reverse dependencies;
4. re-runs semantic contexts that belong to the affected set;
5. reuses cached findings only when none of their dataflow-evidence files intersect the affected set;
6. invalidates the semantic cache automatically when semantic configuration or analyzer version changes.

Other analyzers continue to run normally unless they implement their own safe incremental behavior. This keeps correctness as the default while giving the project-wide semantic engine a meaningful fast path.

The index also records finding lifecycle. Current report findings receive `NEW`, `EXISTING`, or `REOPENED`; previously active findings absent from the current scan are written to `finding-lifecycle.json` as `RESOLVED`.
