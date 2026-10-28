# Ansible 1.5.0 — regression tests

Regression tests for the Keeper Secrets Manager **Ansible** integration, release 1.5.0.
They check that fixed bugs stay fixed and that edge cases keep failing safely.

## What is in this folder

| Path | Purpose |
| --- | --- |
| `playbooks/` | Regression playbooks, grouped by section (`R1` to `R47`) |
| `run_batch.yml`, `run_one.yml` | Run the whole suite (or some sections) in one AAP job and print a PASS/FAIL/SKIP table |
| `create_seed_records.yml`, `seed_helper.py` | Create the fixture records and folders that R38 to R44 read |
| `controller_*.yml`, `ee_*.py` | Checks for Automation Controller (AAP/AWX) |
| `ansible.cfg` | Ansible settings for the suite |

## What the playbooks cover

| Sections | Area |
| --- | --- |
| R1–R4 | Configuration errors and edge cases for `keeper_get`, `keeper_create`, and `keeper_remove` |
| R5–R9 | Unit tests, Jinja2 in config paths, notes handling, cache behavior, output redaction |
| R10–R17, R23, R24, R43, R44 | Records and folders: create, get, rename, delete, remove, and check mode |
| R11, R19, R22, R25 | Cache format and fallback behavior |
| R18, R20, R21, R26, R38, R39, R42, R45, R46 | Plugin documentation, secret redaction, and `no_log` output |
| R40, R41 | Package metadata and the supported `ansible-core` range |

## Run in AAP

The Job Template credential injects the Base64 KSM configuration as `keeper_config`. Many playbooks
read a `config_file` path, so the wrapper decodes `keeper_config` into a private file for the run and
deletes it at the end. Use the execution environment that has the Keeper collection.

**1. Seed the fixtures once per vault.** Job Template with playbook `regression-tests/create_seed_records.yml`
and the KSM credential. Variables: `shared_folder_uid`, `shared_folder_name`, and `ksm1673_shared_b`
(a second shared folder that you create and share to the application by hand; the API cannot create
shared folders). The job prints the UIDs of the records and folders it created. It is idempotent and
never deletes anything.

**2. Run the batch.** Job Template with playbook `regression-tests/run_batch.yml` and the KSM credential.
Variables: `shared_folder_uid` plus the UIDs that the seed job printed, for example:

```yaml
shared_folder_uid: "<UID of a dedicated test shared folder>"
shared_folder_name: "<name of that folder>"
ksm1673_shared_b: "<UID of the second shared folder>"
ksm1673_subfolder: "<UID>"
ksm1673_deep_subfolder: "<UID>"
batch_only: ["R43", "R44"]    # optional: run only these sections
```

The optional variables are listed at the top of `run_batch.yml`. A failing playbook does not stop
the batch, and the job fails at the end if any playbook failed. The playbooks create and delete
records and folders in `shared_folder_uid`, so never point it at production data and do not run two
batches against the same folder.

**Skipped playbooks.** The batch reports these as SKIP because they read a source checkout
(`repo_path`), run the repository unit tests, or test the pip package, and an execution environment
has none of these: R5_1, R9_2, R18_1, R19_1, R27_1, R27_2, R29_2, R29_3, R30_1, R31_1, R32_3, R33_3,
R34_2, R34_3, R35_2, R36_2, R36_3, R37_2, R37_3, R38_2, R39_2, R40_1, R40_2, R41_1, R42_2, R46_2, R47_1.
Run them from a workstation with a checkout of
[`Keeper-Security/secrets-manager`](https://github.com/Keeper-Security/secrets-manager)
(`integration/keeper_secrets_manager_ansible`) and pass `repo_path` and `config_file`.

**Short module names.** Many playbooks call `keeper_get` and the other modules by their short names,
which Ansible resolves only from plugin directories. The batch points `ANSIBLE_LIBRARY`,
`ANSIBLE_ACTION_PLUGINS`, `ANSIBLE_LOOKUP_PLUGINS`, `ANSIBLE_CALLBACK_PLUGINS` and `ANSIBLE_MODULE_UTILS`
at the `plugins/` directories of the installed collection. Set `batch_short_names: false` to turn this off.

## Run one playbook from a workstation

```bash
ansible-playbook playbooks/R10-KSM-845/R10_1_create_in_subfolder.yml -e @vars.json
```

`vars.json` holds `config_file` (a KSM `config.json`), `shared_folder_uid`, `repo_path` for the
playbooks that need it, and the fixture UIDs for R38 to R44. Keep it out of version control.

## Controller tests

`controller_ee_smoke.yml` and `controller_keeper_connectivity.yml` run as Job Templates in AAP
or AWX using a Keeper execution environment. The smoke playbook is offline and expects an SSH
Machine credential. Set `ee_expected_collection_version` to the collection version in the image.
The connectivity playbook is opt-in, reads from Keeper once, and takes its configuration from a
credential injected as `KSM_CONFIG`. Neither prints record contents or configuration values.

## Reference

KSM Ansible integration → https://docs.keeper.io/keeperpam/secrets-manager/integrations/ansible
