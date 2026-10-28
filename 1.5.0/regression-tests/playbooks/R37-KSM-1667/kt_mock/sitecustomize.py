# R29 offline fake vault (KSM-1667). Loaded only when KT_MOCK_SPEC is set. It changes the NETWORK layer only: SecretsManager gets
# a mock response queue as its post function, so every real plugin, KeeperAnsible, the SDK crypto and the callback run for real.
# Every forked Ansible worker imports this file, so each builds its own queue from the spec file.
import json, os
spec_path = os.environ.get("KT_MOCK_SPEC")
if spec_path:
    from keeper_secrets_manager_core import SecretsManager, mock
    _orig = SecretsManager.__init__

    def _init(self, *a, **k):
        _orig(self, *a, **k)
        spec = json.load(open(spec_path))
        rec = mock.Record(title=spec["title"], record_type="login", uid=spec["uid"])
        rec.field("login", spec["login"])
        rec.field("password", spec["password"])
        rec.custom_field("pem_lf", spec["pem_lf"])
        rec.custom_field("pem_crlf", spec["pem_crlf"])
        resp = mock.Response()
        resp.add_record(record=rec)
        queue = mock.ResponseQueue(client=self)
        for _ in range(8):
            queue.add_response(resp)
        self.custom_post_function = queue.post_method
    SecretsManager.__init__ = _init
