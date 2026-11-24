# MAPPING: paper item and file in this directory

Table numbers follow the revised paper (Section 6.2.4<!--ref:subsec:c8-conformance-->); they are written by
`docs/renumber_paper_map.py` from `docs/numbering.json` (see `docs/paper-map.md`, "Numbering"), and file names keep the
names of the objects inside the package.

| Paper | Label | Body printed in the paper | Generated from |
|---|---|---|---|
| Table 10<!--ref:tab:c8-conformance--> | `tab:c8-conformance` | `tables/paper/table13_c8-conformance_rows.tex` | `tables/c8_conformance.csv`, the vector file, the four per-vector reports in `vectors/`, Table 9<!--ref:tab:c7-lifecycle--> of Comment 7 (`table12_c7-lifecycle.csv`) |
| Table 11<!--ref:tab:c8-parameters--> | `tab:c8-parameters` | `tables/paper/table14_c8-parameters_rows.tex` | `tables/c8_parameters.csv` (code defaults of the prototype, testbed values checked against `probe.json` of Comment 7) |
| `\Cei*` macros (`results.tex`) | | `tables/paper/c8_macros.tex` | same inputs as Table 10<!--ref:tab:c8-conformance--> |
| Vector identifiers and rules quoted in Section 6.2.4<!--ref:subsec:c8-conformance--> (TV, IV, KV, SC and DR identifiers) | | `tables/c8_summary.txt`, `tables/c8_vectors_all.csv` | the vector file and the reports |
