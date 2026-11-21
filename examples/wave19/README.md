# Local quota verification

From the repository root, install the project and run the example with a new output directory.

```console
python -m pip install -e .
python examples/wave19/run.py --output wave19-proof
```

The example starts a quota service backed by SQLite and the live authority gateway on loopback. The service checks the signed authorization before changing the quota. Three independent signing roles are exercised through a collector subprocess. It reads with a dedicated credential, probes the running service's quota boundary, and models a fixed burst of demand using the applied quota.

The first change applies quota 8. The second asks for quota 20. The provider acknowledges the write and clamps the stored quota to 10. A tampered provider envelope is rejected, the genuine read causes an acceptance failure, and verified closure is blocked. The operator authorizes a distinct rollback operation. It restores quota 8, passes a new provider read and boundary test, and receives a signed closure. A separate verifier process checks both exported chains.

The output contains public trust policies, signed bundles, source targets, change bytes, raw observations and the measured result. Temporary credentials and databases are outside that output. The example policies and local operator actions are for the loopback run. For an operational setup, provision trust independently and run the collectors in separate security contexts.

```console
blackfox verification verify wave19-proof/quota-20-bundle.json --operation quota-20 --authority wave19-proof/authority.json --provider wave19-proof/provider.json --test wave19-proof/test.json --simulation wave19-proof/simulation.json
```

Run this command soon after the example for a current verdict. Once the evidence age expires, the command still reports the historical outcome when the signatures and policies remain valid, and exits 1.
