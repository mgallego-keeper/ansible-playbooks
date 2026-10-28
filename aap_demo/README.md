# Keeper Secrets Manager AAP QA Demo

This guide is for Mateo's hands-on demo with Austin and Victoria. It covers
end-to-end testing of the Ansible v1.5.0 release on Ansible Automation Platform
(AAP), using dedicated QA vaults and verbose job output. The goal is to verify
real vault changes, diagnose expected failures, and inspect sensitive-data
exposure rather than treating a successful job as sufficient evidence.

The existing repository examples are unchanged. This directory contains a
separate, repeatable demo suite.

## Source and execution environment

- Release PR: https://github.com/Keeper-Security/secrets-manager/pull/982
- Reference revision: `8402e39513ac3de65fe5e25baf9e1e021ed18371`
- QA image: `docker.io/keepersecurityinc/keeper-secrets-manager-tower-ee-qa:1.5.0`
- Image repository: https://hub.docker.com/r/keepersecurityinc/keeper-secrets-manager-tower-ee-qa
- Controller setup: https://docs.keeper.io/keeperpam/secrets-manager/integrations/ansible/ansible-automation-controller
- Plugin reference: https://docs.keeper.io/keeperpam/secrets-manager/integrations/ansible/ansible-plugin

The reference revision is the PR head inspected when preparing this suite.
The image tag is mutable, and its version number does not establish its source
revision. Record the image digest and confirm the build includes the intended
PR revision. The public docs provide setup guidance, but the PR's module
documentation is the reference for the new folder interfaces.

## Prepare the QA vault

1. Choose a dedicated QA shared folder and give the QA KSM application the
   permissions needed for record and folder CRUD.
2. Initialize a reusable Base64 KSM configuration for that application. Do not
   reuse a one-time initialization token as the normal job credential.
3. Record the top-level shared-folder UID. It is not a subfolder UID.
4. Optional: prepare a second application with read-only access for permission
   tests after the core demo.
5. Optional: prepare the harmless attachment described under managed-host copy.

The suite creates scenario folders named
`AAP-Demo-<scenario>-<demo_run_id>` inside the selected shared folder. CRUD and
forced deletion are intentional in these QA fixtures. The confirmation flag
is a guard against launching these templates with the wrong vault credentials;
it does not grant permissions or verify that an account really is QA.

## Configure AAP

Use the navigation labels in the current AAP UI. Older screenshots in the
Keeper controller guide put some of these resources under different menus.

### Execution environment

Add or select the QA execution environment with the image above. For a mutable
QA tag, select **Always pull container before running**. Record the image digest.

Do not use an old runtime-install example for this demo. Do not add an unpinned
`collections/requirements.yml` that installs a released collection over the
collection in the QA image. A project-local collection can take precedence
over an execution-environment collection.

### KSM credential

Create a custom credential type with this input configuration:

```yaml
fields:
  - id: keeper_config
    type: string
    label: Keeper Config Base64
    secret: true
required:
  - keeper_config
```

Use this injector configuration:

```yaml
extra_vars:
  keeper_config: "{{ keeper_config }}"
```

Create a credential of that type and put the initialized QA configuration in
its secret input. Attach it to the demo job templates. Never put the
configuration in the repository or ordinary template variables.

### Project and job templates

Use `https://github.com/mgallego-keeper/ansible-playbooks.git` as the project
source. Select the branch or commit that contains this directory, select the
QA execution environment, and sync the project before launching jobs.
Uncommitted local files are not available to AAP.

For playbooks 01-05 and 07:

- Select an inventory with permission to run local jobs.
- Select the QA execution environment explicitly on the template.
- Attach the KSM credential.
- Set job type to **Run**, not **Check**. Playbook 03 applies check mode only
  to modules that support it.
- Set verbosity to **3 Debug**, equivalent to `-vvv`.
- Leave job diffs disabled. Secret-copy tasks also disable their own diffs.

These playbooks use `localhost` with a local connection. That is the
execution-environment container, not the controller host, Mateo's laptop, or
a remote inventory server. Playbook 06 is the separate real-managed-host test.

Copy the non-secret values in `vars.example.yml` into the template Variables
field and replace the shared-folder placeholder:

```yaml
shared_folder_uid: "YOUR_QA_SHARED_FOLDER_UID"
demo_qa_confirmed: true
demo_run_id: "demo-austin-victoria"
demo_keep_fixtures: false
demo_protect_sensitive_tasks: false
```

If `demo_run_id` is omitted, the playbook uses the AAP job ID or a UTC
timestamp. Use an explicit ID when scanning logs or preparing an attachment.
Use a fresh ID after a retained or interrupted run to avoid mixing evidence.

## Presenter sequence

| Time | Action | Evidence to show |
| --- | --- | --- |
| 5 minutes | Explain template, job, execution environment, KSM application, and managed host | Where code runs and where credentials enter the job |
| 10 minutes | Run `01_preflight.yml` | Collection locations, module resolution, SDK versions, live QA folder access |
| 10 minutes | Run `02_folder_record_lifecycle.yml` | Nested creation, reads, updates, stable UIDs, idempotence, safe and forced deletion |
| 10 minutes | Run `03_validation_and_check_mode.yml` | Specific failures, unchanged vault state after check mode, rescue handling |
| 10 minutes | Run `04_cache_and_complex_fields.yml` | Empty complex fields, snapshot behavior, unusable-cache warning and live fallback |
| 10 minutes | Run `05_verbose_log_checks.yml` twice and inspect evidence | Unprotected output versus protected tasks, including internal warnings |
| 5 minutes | Let Austin and Victoria rerun or diagnose a test | They can identify the failure class and verify the actual result |

Run the managed-host copy as an additional exercise or replace part of the
core sequence with it. Leave time for each analyst to drive the UI.

### Preflight

`01_preflight.yml` is non-mutating. Inspect the actual paths printed by
`ansible-doc`, not only the list of installed versions. A listed v1.5.0
collection does not prove that every module is resolving from that location.
Capture the image digest and source provenance separately.

### Folder and record lifecycle

`02_folder_record_lifecycle.yml` verifies:

- Creation of a folder and deeper subfolder.
- Repeating creation under the same parent returns the same UID and
  `changed: false`.
- Path lookup returns the expected UID, parent, and shared-folder UID.
- The existing shared-folder-root record interface still creates a record.
- `subfolder_uid` creates a login record in the selected nested folder.
- Password, custom-field, and fully qualified lookup results equal the
  synthetic fixtures.
- Password and notes updates are read back without a registered cache.
- Rename keeps folder identity; repeating it reports `changed: false`.
- Nonempty deletion without force fails specifically because it is nonempty.
- Record removal, empty-folder deletion, and repeated deletion behave as expected.
- Explicit forced parent deletion removes the descendant folder and its record.

Use Keeper's UI during the job or use separate manual fixtures to confirm root
versus subfolder record placement. The record getter returns field data, not
an independent placement assertion. The suite prints the compatibility record
UID before deleting it; it does not pause for UI inspection.

Important interface distinctions:

- `keeper_create` uses `shared_folder_uid` and optional `subfolder_uid`.
- The old `keeper_create.folder_uid` is rejected, not retained as an alias.
- Folder rename and delete legitimately identify their target with `folder_uid`.
- Folder deletion uses `force_deletion`, not `force`.
- Folder rename changes the name, not the parent location.

### Expected failures and check mode

`03_validation_and_check_mode.yml` deliberately produces failed tasks.
Assertions require specific error messages; an unrelated network or credential
error does not count as a successful negative test.

It covers literal slash names, start-folder lookup, unknown options, null
values, numeric names, mutually exclusive lookup options, padded renames,
obsolete parameters, and the unsupported direct `force` option. It also
verifies that a copy-related `force` action-group default does not disable
nonempty-folder protection.

The rename and delete preview tasks use `check_mode: true`. A fresh folder
lookup must still find the original name afterward. The `block` and `rescue`
example verifies the specific missing-folder error before accepting it.

Never feed a lookup with `folder_name | default(omit)` into deletion without
checking its identity: omitting both name and path returns the start folder.

### Cache and empty complex fields

`04_cache_and_complex_fields.yml` creates an address record with an empty
standard address field and empty custom name/host fields. It verifies that
creation succeeds rather than crashing on `value: []`.

The cache exercise verifies a usable registered snapshot, updates the live
record, and demonstrates that the old snapshot stays stale. A fresh read and
a regenerated cache return the new password. The unusable-cache task must
return the live value and emit the fallback warning.

This is the encrypted, per-playbook registered record cache. It is not the
separate disaster-recovery disk cache. Do not transfer these snapshots between
jobs: their key derivation includes the execution host's name.

This playbook does not prove absence of pickle execution, validate every
binary/file metadata round trip, or create a valid legacy encrypted cache.
Those require the PR's isolated cache/security tests. Never test an untrusted
pickle payload against an older vulnerable plugin inside AAP.

## Inspect verbose log exposure

The diagnostic run intentionally leaves sensitive task output unprotected,
using only synthetic record values. Do not hide the main run upfront.

Run `05_verbose_log_checks.yml` twice:

1. **Diagnostic pass:** `demo_protect_sensitive_tasks: false`, verbosity 3.
2. **Protected pass:** `demo_protect_sensitive_tasks: true`, the same verbosity.

Keep automatic cleanup enabled between these passes if reusing the same run
ID. Optionally repeat at verbosity 4 for focused connection/internal logging.

The playbook does not deliberately debug retrieved secret values. It exercises
normal task results, normalized record data, lookup, copy, base64-returning
`slurp`, a failure message, idempotent-rename verbose output, and a
duplicate-name warning. Duplicate-name lookup must fail rather than choose
one of the folders.

AAP uses its own stdout callback; `keeper_redact` does not protect AAP job
output. Also, do not assume `no_log` filters every direct `Display` or SDK log
message. The protected pass explicitly tests that boundary. Inspect internal
rename messages and warnings even when the task result is censored.

### Scan exported evidence

This repository is public. Store job exports, QA credentials, and local
attachments only under the ignored `aap_demo/artifacts/` directory, with
appropriate local permissions. Ignoring a file is not encryption.

Download job stdout. If inspecting job events through the AAP API, include
every page of `/api/controller/v2/jobs/<job_id>/job_events/` for current
platform-gateway deployments. Older controller deployments use
`/api/v2/jobs/<job_id>/job_events/`. Use the route reported by your instance,
and follow every `next` link. A single page is not complete evidence.

Run the standard-library-only scanner:

```bash
python3 aap_demo/tools/scan_job_logs.py \
  aap_demo/artifacts/diagnostic-stdout.txt \
  aap_demo/artifacts/diagnostic-events.json \
  --run-id demo-austin-victoria
```

It checks the known canaries, common JSON-escaped representations, and base64
representations such as `slurp` output. Its report contains labels and
locations, not matched values or raw log lines.

To inspect the initialized configuration and its component values, put
labeled strings in a local, ignored JSON object and add
`--secrets-file aap_demo/artifacts/sensitive-inputs.json`. Do not pass real
credentials with `--canary`, since command-line arguments can be recorded in
shell history and process listings.

For the protected pass, `--fail-on-match` can turn matches into a nonzero exit
status:

```bash
python3 aap_demo/tools/scan_job_logs.py \
  aap_demo/artifacts/protected-stdout.txt \
  aap_demo/artifacts/protected-events.json \
  --run-id demo-austin-victoria \
  --fail-on-match
```

`demo_emit_positive_control: true` deliberately prints a separate
`QA_LOG_SCAN_POSITIVE_CONTROL` marker. Use it only to confirm that an export
and scanner actually capture emitted output. Turn it off for the protected
pass.

Classify each hit before reporting it:

| Exposure | Interpretation |
| --- | --- |
| Unprotected task arguments or return values | Ansible output exposure, often expected without `no_log` |
| The optional positive-control marker | Deliberately emitted scanner control |
| Protected task values in normal results | Investigate whether protection was applied and honored |
| Direct SDK/Display warnings or verbose messages | Inspect separately from censored task results |
| Reusable configuration, private/app keys, initialization tokens | Sensitive credential exposure, including in QA |
| Folder names/UIDs decrypted from Ansible Vault | Encryption at rest is not output redaction |

A local simulated-backend run of the pinned PR source with
`ansible-core 2.19.2` found folder/error canaries in idempotent-rename verbose output,
duplicate-name warnings, and failure diagnostics even with sensitive tasks
marked `no_log: true`. The password, notes, and custom-field canaries did not
match that protected run. These are local observations using the standard
Ansible callback, not confirmed behavior of AAP's callback. Verify them in
the actual AAP jobs before drawing a platform-specific conclusion.

A zero-match result is not proof of zero exposure. The scanner cannot identify
unknown secrets, all encodings, partial values, screenshots, or evidence that
was never exported. JSON reports are available with `--json`.

## Test a real managed host

`06_managed_host_copy.yml` uses the repository's `my_systems` inventory group.
Put a disposable Linux host in that group and attach the needed machine
credential to the template. Do not use a local-connection inventory host if
claiming remote delivery.

Create a harmless attachment without a trailing newline:

```bash
mkdir -p aap_demo/artifacts
printf 'QA_CANARY_FILE_demo-austin-victoria' > aap_demo/artifacts/aap-demo.txt
```

Attach it to a QA record shared with the KSM application. Add these non-secret
variables to the template:

```yaml
demo_run_id: "demo-austin-victoria"
demo_copy_record_uid: "YOUR_QA_RECORD_UID"
demo_copy_attachment_name: "aap-demo.txt"
```

The playbook copies the attachment into an isolated remote temporary
directory, checks exact content and mode `0600`, requires the second copy to
report `changed: false`, and removes its temporary directory afterward.
It does not delete the manually prepared attachment record.

## Cleanup and repeatability

Self-contained scenarios run cleanup in `always`, including after a test
failure. Cleanup failures remain visible. With
`demo_keep_fixtures: true`, automatic cleanup is skipped and job artifacts
include `demo_cleanup_folder_uid` and `demo_cleanup_root_name`.

Retaining fixtures does not undo explicit delete operations already tested
inside a scenario. It also does not keep temporary filesystem copies.

Use `07_cleanup.yml` to remove a retained scenario folder. Supply its exact
UID and name from the earlier job, alongside the same QA shared-folder UID
and KSM credential. The playbook checks current identity and ancestry before
forced deletion. If the folder is already absent, it sends no delete.

If the lifecycle job failed while its shared-folder-root compatibility record
existed and fixtures were retained, remove that separate record by its logged
UID. Folder cleanup cannot remove a record outside that folder.

## Capture QA evidence

For each case record:

- Job URL and template/playbook.
- Playbook commit, PR source revision, image digest, and runtime versions.
- QA application and shared-folder identifiers, without credential material.
- Expected result and actual vault/host state.
- Expected failures, idempotence results, and check-mode results.
- Log-hit labels/locations and their classification.
- Cleanup result or remaining fixture UIDs.

Have Austin and Victoria distinguish project-sync, image/startup,
collection-resolution, credential/access, module-validation, and server/API
failures. Finish with each analyst launching and diagnosing a case themselves.

For a later extended regression pass, add read-only/server-refused operations,
unshared versus unreadable folders, quoted numeric names, Ansible
Vault-encrypted arguments, and folder formats produced by older/newer clients.
The upstream PR tests cover these boundaries; the introductory demo suite
does not reproduce all of them.

## Local verification

Run the scanner unit tests without a Keeper credential:

```bash
python3 -m unittest discover -s aap_demo/tests -v
```

For syntax checks, use the QA collection rather than an older local release.
The following checks syntax inside the intended image and does not execute
vault operations:

```bash
for playbook in aap_demo/0*.yml; do
  docker run --rm \
    --entrypoint ansible-playbook \
    --volume "$PWD:/work:ro" \
    --workdir /work \
    docker.io/keepersecurityinc/keeper-secrets-manager-tower-ee-qa:1.5.0 \
    --syntax-check "$playbook" || break
done
```

Syntax checks and mocked/local checks are not an AAP end-to-end pass. Complete
the live runs and evidence inspection in the QA environment before treating
the suite as validated on your platform.
