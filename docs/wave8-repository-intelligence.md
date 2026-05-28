# Wave 8 Repository Intelligence

Wave 8 adds a conservative repository-intelligence layer to IX-BlackFox.

It is designed to make AI-assisted code-change boundaries more inspectable before a human reviewer is asked to trust a patch, repair candidate, workflow change, or evidence bundle.

Wave 8 does not make the repository self-authorizing. It does not certify correctness. It does not replace human review. It gives maintainers a deterministic evidence path for understanding what a proposed repository change may touch.

## What Wave 8 adds

Wave 8 adds the following repository-intelligence pipeline:

```
inventory
  -> Python code graph
  -> dependency map
  -> source-test coverage map
  -> architectural memory
  -> conservative impact analysis
  -> digest-chained evidence
  -> exportable Wave 8 report
```
The implementation lives under:
```
src/ix_blackfox/repository/
```
The CI evidence runner lives at:
```
scripts/run_wave8_repository_intelligence_ci.py
```
The dedicated workflow lives at:
```
.github/workflows/wave8-repository-intelligence.yml
```
Design rule

Wave 8 treats repository intelligence as review evidence, not as automatic authority.

The core rule remains:
```
AI proposes. Humans decide.
```
Wave 8 supports that rule by producing evidence about repository structure and likely change impact before an AI-generated or AI-assisted change is trusted.

Repository inventory

The inventory layer scans repository files without executing repository code.

It records:

repository-relative path
file role
file size
SHA-256 digest
sensitivity classification
executable flag
generated/artifact flag
basic metadata

Supported file roles include:

source
test
documentation
configuration
workflow
script
license
artifact
unknown

Sensitivity classifications include:

normal
policy relevant
security relevant
release relevant
generated or artifact

The inventory scanner intentionally ignores common non-review surfaces such as:

.git/
.mypy_cache/
.pytest_cache/
.ruff_cache/
.tox/
.venv/
__pycache__/
build/
dist/
htmlcov/
.blackfox-artifacts/

This keeps the evidence focused on reviewable repository content instead of transient local artifacts.

Python code graph

The Python graph layer parses Python files with ast.

It does not import repository modules. It does not execute repository code.

It extracts:

modules
classes
functions
methods
uppercase top-level constants
import edges
internal import relationships where safely resolvable
syntax-error paths

Graphable Python roles are:

source files
test files
script files

If a Python file cannot be parsed, Wave 8 records the syntax-error path instead of pretending the graph is complete.

Dependency mapping

The dependency map combines metadata and graph evidence.

It records:

build dependencies from pyproject.toml
runtime dependencies from pyproject.toml
optional/development dependencies from pyproject.toml
GitHub Actions workflow uses: dependencies
internal import edges from the Python graph
external imports observed by the graph when they are not standard-library modules
sensitive dependency/config paths

Sensitive paths include files such as:

pyproject.toml
workflow YAML files
policy/config files
scripts
license/notice files
security-relevant source areas

The dependency map does not claim perfect supply-chain analysis. It provides deterministic dependency evidence that maintainers can review.

Source-test coverage map

Wave 8 builds a conservative source-test map.

It uses three signals:

direct source/test path mirrors
Python graph evidence showing a test imports a source module
same-subsystem filename stem matching

The map records:

source-test links
confidence values
link reasons
inferred subsystems
orphan source paths
orphan test paths

A missing inferred test does not prove a source file is untested. It means Wave 8 could not infer a direct source-test relationship from the available static evidence.

Architectural memory

Wave 8 adds structured architectural memory.

This is not free-form AI memory. It is a set of digestable architecture records that describe stable subsystem boundaries.

Each architecture record includes:

record ID
subsystem ID
owned paths
responsibilities
constraints
evidence expectations
wave number
metadata

Default architectural memory covers IX-BlackFox subsystems such as:

repo governance
CI workflows
scripts
runtime
brains
authoring
workflow
sandbox
governance
forge
memory
vault
sentinel
repository
reliability
interface
docs

The repository-intelligence subsystem itself is explicitly represented as:
```
src/ix_blackfox/repository
tests/repository
```
Wave 8 can also add discovered subsystem records from the coverage map. Those discovered records are intentionally marked as inferred, not as perfect architecture truth.

Conservative impact analysis

The impact analyzer takes changed paths and produces a review-oriented impact report.

It uses:

repository inventory
dependency map
source-test coverage map
architectural memory

The impact report includes:

changed paths
impacted paths
impacted tests
impacted subsystems
findings
maximum severity
whether human review is required
recommended validation commands
bound input digests

Impact severities include:

none
low
medium
high
critical

Wave 8 escalates review attention for paths that affect:

CI workflows
scripts
license files
policy files
release metadata
security-relevant source areas
unknown changed paths
source files with no inferred test relationship
cross-subsystem changes

The impact analyzer is intentionally conservative. It is meant to help a reviewer ask better questions, not to prove a patch is safe.

Evidence ledger

Wave 8 produces digest-chained repository evidence.

The required Wave 8 event sequence is:
inventory_snapshot
code_graph_built
dependency_map_built
coverage_map_built
architecture_memory_bound
impact_analyzed
report_exported
```
Each receipt records:

receipt ID
event type
summary
payload digest
run ID
sequence number
previous receipt digest
timestamp
metadata
receipt digest
```
This preserves IX-BlackFox's evidence posture:
```
claim -> evidence -> digest -> chain -> review
```
Report export

The top-level Wave 8 report includes:

schema version
wave number
run ID
head SHA
root name
generated timestamp
pass/fail state
artifact digests
summary
impact report
evidence snapshot
scope note
optional full inventory/graph/dependency/coverage/memory details

The schema version is:
```
wave8.repository_intelligence.v1
```
Default CI report path:
```
.blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json
```
Default CI evidence path:
```
.blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json
```
CLI usage

Wave 8 adds repository-intelligence commands through the existing IX-BlackFox CLI.

Repository scan:
```
blackfox repository scan --root . --json
```
Repository impact analysis:
```
blackfox repository impact \
  --root . \
  --changed src/ix_blackfox/repository/report.py \
  --json
```
Repository report generation:
```
blackfox repository report \
  --root . \
  --changed src/ix_blackfox/repository/report.py \
  --head-sha local \
  --run-id wave8-local \
  --output .blackfox-artifacts/wave8/wave8-local-report.json \
  --summary-only \
  --json
```
The alias also works:
```
blackfox repo-intel scan --root . --json
```
CI usage

Run the Wave 8 CI evidence script locally:
```
python scripts/run_wave8_repository_intelligence_ci.py \
  --head-sha local
```
Write custom report and evidence paths:
```
python scripts/run_wave8_repository_intelligence_ci.py \
  --head-sha local \
  --output .blackfox-artifacts/wave8/wave8-repository-intelligence-ci-report.json \
  --evidence-output .blackfox-artifacts/wave8/wave8-repository-intelligence-evidence.json
```
Analyze custom changed paths:
```
python scripts/run_wave8_repository_intelligence_ci.py \
  --head-sha local \
  --changed src/ix_blackfox/repository/report.py \
  --changed scripts/run_wave8_repository_intelligence_ci.py
```
Include full inventory, graph, dependency, coverage, and architecture-memory details:
```
python scripts/run_wave8_repository_intelligence_ci.py \
  --head-sha local \
  --include-full
```
Dedicated GitHub Actions workflow

Wave 8 adds:
```
.github/workflows/wave8-repository-intelligence.yml
```
The workflow performs the following checks:
```
python -m pytest tests/repository -q
python -m pytest tests/ci/test_wave8_repository_intelligence_ci_integration.py -q
python -m pytest tests/ci/test_wave8_repository_intelligence_workflow_contract.py -q
python -m compileall -q src/ix_blackfox/repository scripts tests/repository tests/ci
python scripts/run_wave8_repository_intelligence_ci.py --head-sha "${{ github.sha }}"
```
The workflow uploads the Wave 8 report and evidence snapshot as artifacts.

The workflow is intentionally offline-oriented. It does not require model API keys, model providers, external services, or production credentials.

What a passing Wave 8 report means

A passing Wave 8 report means:

repository inventory completed
Python code graph completed with zero syntax-error paths
dependency map completed
source-test coverage map completed
architectural memory snapshot completed
conservative impact report completed
evidence receipt chain validated
report export completed

It means the Wave 8 repository-intelligence contracts produced deterministic evidence.

What a passing Wave 8 report does not mean

A passing Wave 8 report does not mean:

the repository is production-ready
the code is formally verified
the code is certified
the code is approved by any government or defense organization
the dependency graph is perfect
the test map is complete
every possible runtime effect was identified
a model-generated patch is safe
a human reviewer can be skipped
autonomous execution authority has been granted

Wave 8 provides review evidence. It does not provide automatic trust.

DevSecOps relevance

Wave 8 is useful for DevSecOps because it gives reviewers a structured way to inspect repository-change boundaries.

It helps answer:

What files changed?
What source modules are related?
What tests are likely relevant?
What subsystem boundaries are touched?
Does the change affect CI, scripts, policy, licensing, or security-sensitive code?
What commands should be run before review?
What evidence was generated?
Can the evidence chain be inspected?

This supports a stronger AI-assisted software workflow:
```
model output -> repository intelligence -> impact evidence -> validation commands -> human review
```
DoD/T&E relevance

Wave 8 is relevant to test, evaluation, assurance, and governed AI-assisted engineering workflows because it treats model output as untrusted input and requires repository evidence before trust.

It supports the kind of review posture where evaluators can inspect:

policy-sensitive paths
CI-bound evidence
receipt chains
impacted subsystems
recommended tests
architecture constraints
human-review findings
bounded claims

Wave 8 should not be described as DoD-approved, certified, deployed, affiliated, or production-ready. It is a source-available research implementation that produces repository-intelligence evidence for review.

Operator workflow

A practical operator flow:

receive or generate a proposed patch
identify changed paths
run Wave 8 impact analysis
inspect impacted tests and subsystems
run recommended commands
inspect evidence JSON
decide whether the change needs more tests, rejection, revision, or human approval

Example:
```
blackfox repository impact \
  --changed src/ix_blackfox/runtime/brain_repair.py \
  --json
```
Then run the recommended commands from the impact report.

Evidence boundaries

Wave 8 evidence is strongest when:

changed paths are accurate
repository files are present in the working tree
Python files parse successfully
tests follow recognizable naming/path patterns
imports are statically visible
architecture records match the current repo layout

Wave 8 evidence is weaker when:

code uses dynamic imports heavily
tests are indirectly wired through fixtures only
generated code is involved
files are deleted before inventory capture
architectural ownership is ambiguous
changed paths are stale or misspelled

The system reports unknown changed paths instead of hiding them.

Implementation map

Core files:
```
src/ix_blackfox/repository/models.py
src/ix_blackfox/repository/inventory.py
src/ix_blackfox/repository/python_graph.py
src/ix_blackfox/repository/dependencies.py
src/ix_blackfox/repository/coverage_map.py
src/ix_blackfox/repository/architecture_memory.py
src/ix_blackfox/repository/impact.py
src/ix_blackfox/repository/evidence.py
src/ix_blackfox/repository/report.py
src/ix_blackfox/repository/cli.py
```
Script:
```
scripts/run_wave8_repository_intelligence_ci.py
```
Workflow:
```
.github/workflows/wave8-repository-intelligence.yml
```
Tests:
```
tests/repository/
tests/ci/test_wave8_repository_intelligence_ci_integration.py
tests/ci/test_wave8_repository_intelligence_workflow_contract.py
tests/docs/test_wave8_repository_intelligence_docs.py
tests/interface/test_cli.py
```
