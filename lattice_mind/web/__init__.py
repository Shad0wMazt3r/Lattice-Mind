"""Web-layer helpers (structured HTTP models)."""

from lattice_mind.web.request_models import (
    HTTPRequestSpec,
    HTTPResponseRecord,
    apply_param_payload,
    clone_http_request_spec,
    record_from_adapter_response,
    request_spec_for_challenge_url,
    request_spec_from_form_record,
    request_spec_from_jsonable,
    request_spec_to_jsonable,
    spec_to_adapter_args,
)

__all__ = [
    "HTTPRequestSpec",
    "HTTPResponseRecord",
    "apply_param_payload",
    "clone_http_request_spec",
    "record_from_adapter_response",
    "request_spec_for_challenge_url",
    "request_spec_from_form_record",
    "request_spec_from_jsonable",
    "request_spec_to_jsonable",
    "spec_to_adapter_args",
]
