# NIPoK-SE: reproducibility package

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24371174.svg)](https://doi.org/10.5281/zenodo.24371174)

Formal models, testbed, benchmark harnesses and derived results for the paper

> Dong Bui-Huu, Thang Trinh-Cao, Vinh Pham-An, Tan Le-Nhat and Khuong Nguyen-An. *A Privacy-Preserving Framework using
> Non-Interactive Proofs of Knowledge for End-to-End Secure Authentication in Open Banking*. Submitted to the Journal of
> Network and Computer Applications, 2026.

Version 3.1 (doi:10.5281/zenodo.24525751) accompanies the revised manuscript; doi:10.5281/zenodo.24371174 resolves
to the latest version. Version 3.0 (doi:10.5281/zenodo.24371175) accompanied an earlier draft of the revised manuscript. Version 2.0 (doi:10.5281/zenodo.21904704)
accompanied the submitted manuscript; `CHANGELOG.md` lists the differences.

## Contents

| Directory | Contents | Paper |
|---|---|---|
| `formal/` | ProVerif, CryptoVerif and EasyCrypt models and the script that runs them | Section 5 |
| `testbed/` | Three-cluster Kubernetes testbed: NIPoK and the six baseline mechanisms, authorization server, TPP, customer-agent, Helm charts, deployment scripts, JMH and k6 harnesses, measurement drivers | Sections 4, 6.1 and 6.2 |
| `experiments/submission/` | Results of the submitted version, kept for comparison | Submitted manuscript |
| `experiments/r1-c6-statistical-evaluation/` | Analysis and results of the repeated JMH and load-test measurements | Section 6.2.2 |
| `experiments/r1-c7-security-cost-ablation/` | Analysis and results of the cost breakdown and the operational tests | Section 6.2.3 |
| `experiments/r1-c8-conformance/` | Test vectors, independent implementations and conformance tables | Section 6.2.4 |
| `docs/` | Reproduction guide, paper map, measurement environment, deployment secrets, provenance | |

The names `r1-c6`, `r1-c7` and `r1-c8` refer to Comments 6, 7 and 8 of Reviewer 1, which these experiments answer.
`docs/paper-map.md` gives the file behind every figure, table and section of the paper.

## Code, derived results and raw data

The repository contains the code and the derived results: the figures, tables, data files and reports that hold the
numbers of the paper. The raw measurement data of every campaign (JMH result files, k6 summaries and logs, metrics
extracted from Prometheus and Istio, campaign manifests) are archived on Zenodo in a separate dataset record,
https://doi.org/10.5281/zenodo.24370110. Zenodo also archives each release of this repository. The analysis
scripts regenerate every derived result from the raw data.

## Getting started

`docs/reproduce.md` describes three levels of reproduction:

1. regenerate the derived results from the raw data, run the formal models and run the conformance vectors, without a
   testbed;
2. deploy the testbed and run one authorization journey per mechanism;
3. repeat the measurement campaigns; `docs/environment.md` describes the host of the published measurements and the
   limits of reproduction.

## Security

The repository contains no credentials, private keys or certificates. Deployment secrets are generated on the
deployment host by `testbed/secrets/generate-secrets.sh` and are never committed (`docs/secrets.md`). The demo values
published with version 2.0 are no longer used.

## License and citation

The package is released under the MIT license (`LICENSE`). Citation metadata are in `CITATION.cff`. Please cite the
article and the version of the package that you used:

| Record on Zenodo | DOI |
|---|---|
| Version 3.1 of this package (revised manuscript) | [10.5281/zenodo.24525751](https://doi.org/10.5281/zenodo.24525751) |
| Version 3.0 of this package (earlier draft of the revised manuscript) | [10.5281/zenodo.24371175](https://doi.org/10.5281/zenodo.24371175) |
| All versions from 3.0 on (resolves to the latest) | [10.5281/zenodo.24371174](https://doi.org/10.5281/zenodo.24371174) |
| Raw measurement data (used by versions 3.0 and 3.1) | [10.5281/zenodo.24370110](https://doi.org/10.5281/zenodo.24370110) |
| Version 2.0 (submitted manuscript) | [10.5281/zenodo.21904704](https://doi.org/10.5281/zenodo.21904704) |
