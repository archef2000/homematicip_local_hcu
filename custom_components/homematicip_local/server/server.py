from collections.abc import Mapping
import functools
import inspect
import json
import logging
import ssl
import threading
import time
import types
from typing import (
    Any,
    Callable,
    Literal,
    ParamSpec,
    TypeAlias,
    TypeVar,
    TypedDict,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
    overload,
)
import uuid
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning
from websocket import WebSocket, WebSocketApp

from .types.hmip_system import Event
from .types.hmip_system import SystemState
from .types.hmip_system_requests import (
    DeviceControlRequestBodies,
    GroupHeatingRequestBodies,
    GroupLinkedControlRequestBodies,
    GroupProfileRequestBodies,
    GroupSwitchingRequestBodies,
    HmIPDeviceControlRequestPaths,
    HmIPGroupHeatingRequestPaths,
    HmIPGroupLinkedControlRequestPaths,
    HmIPGroupProfileRequestPaths,
    HmIPGroupSwitchingRequestPaths,
    HmIPHomeHeatingRequestPaths,
    HmIPHomeRequestPaths,
    HmIPHomeSecurityRequestPaths,
    HmIPRoleRequestPaths,
    HmIPSystemGetStateForClientResponseBody,
    HmIPSystemGetStateResponseBody,
    HmIPSystemGetSystemStateResponseBody,
    HmIPSystemRequestPaths,
    HmIPSystemSetExtendedZonesActivationResponseBody,
    HmIpSystemResponseBody,
    HomeHeatingRequestBodies,
    HomeRequestBodies,
    HomeSecurityRequestBodies,
    RoleRequestBodies,
)
from .types.messages import (
    ConfigTemplateRequestBody,
    ConfigUpdateRequestBody,
    HmipSystemEventBody,
    PluginMessage,
)

plugin_id = "com.homeassistant.custom"


class PendingEntry(TypedDict):
    """Type for entries stored in HCUController._pending.

    Keys:
    - expected_type: the response type expected for a given request id
    - event: a threading.Event used to signal response arrival
    - response: the response payload (or None until set)
    """

    expected_type: str
    event: threading.Event
    response: dict[str, Any] | None  # pyright: ignore[reportExplicitAny]


PendingMap: TypeAlias = dict[str, PendingEntry]


def make_request(ip: str, method: str, path: str, data: dict[str, Any]):  # pyright: ignore[reportExplicitAny]
    headers = {"VERSION": "12"}
    # Suppress only this self-signed HTTPS request warning
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        return requests.request(
            method,
            f"https://{ip}:6969/{path}",
            json=data,
            headers=headers,
            verify=False,
        )


def confirm_auth_token(ip: str, auth_token: str, activation_key: str) -> str | None:
    data = {
        "authToken": auth_token,
        "activationKey": activation_key,
    }
    response = make_request(ip, "POST", "hmip/auth/confirmConnectApiAuthToken", data)
    if response.status_code == 200:
        return str(response.json()["clientId"])  # pyright: ignore[reportAny]
    else:
        print("Error:", response.status_code, response.text)


def init_hcu_plugin(ip: str, activation_key: str):
    if len(activation_key) != 6:
        raise ValueError("Invalid activation key length")
    data = {
        "pluginId": plugin_id,
        "activationKey": activation_key,
        "friendlyName": {
            "de": "Home Assistant Custom Plugin",
            "en": "Home Assistant Custom Plugin",
        },
    }
    response = make_request(ip, "POST", "hmip/auth/requestConnectApiAuthToken", data)

    if response.status_code == 200:
        auth_token: str = response.json()["authToken"]  # pyright: ignore[reportAny]
        client_id = confirm_auth_token(ip, auth_token, activation_key)
        return {"auth_token": auth_token, "client_id": client_id}

    print("Error:", response.status_code, response.text)


logging.basicConfig(level=logging.INFO)

# Internal generic for type helper parameters (avoid pervasive Any complaints)
_TType = TypeVar("_TType")


def _is_typed_dict(tp: object) -> bool:
    if not isinstance(tp, type):  # not a class
        return False
    if not hasattr(tp, "__annotations__"):
        return False
    return hasattr(tp, "__total__") or hasattr(tp, "__required_keys__")


def _validate_typed_dict(
    name: str,
    spec: type,
    value: object,
    issues: list[str],
    *,
    allow_extra: bool = False,
    record_unexpected: bool = True,
) -> None:
    """Validate a TypedDict-like object.

    allow_extra controls whether unexpected keys raise (False) or are just
    collected as issues (True). Used with union probing to avoid premature
    failure before picking the best variant.
    """
    if not isinstance(value, dict):
        issues.append(
            f"{name}: expected dict (TypedDict {spec.__name__}), got {type(value).__name__}"
        )
        return
    annotations: dict[str, object] = getattr(spec, "__annotations__", {})  # type: ignore[reportExplicitAny]
    for k, tp in annotations.items():
        if k not in value:  # type: ignore[reportUnknownArgumentType]
            # Suppress missing-key report when the field is Optional (i.e. Union[..., None])
            is_optional = False
            try:
                if _is_union_type(tp):
                    args = get_args(tp)
                    # Optional if a NoneType member exists
                    if any(a is type(None) for a in args):  # noqa: E721
                        is_optional = True
                elif tp is None or tp is type(None):  # direct None annotation
                    is_optional = True
            except Exception:  # pragma: no cover - defensive
                pass
            if not is_optional:
                issues.append(f"{name}.{k}: missing key")
            continue
        # Use full runtime checker (handles unions & nested TypedDicts)
        _runtime_type_check(tp, value[k], f"{name}.{k}", issues)
    if record_unexpected:
        extras = [str(k) for k in value.keys() if k not in annotations]
        if extras:
            for ex in extras:
                issues.append(f"{name}.{ex}: unexpected key")
            if not allow_extra:
                raise KeyError(f"{name}: unexpected key(s) {extras}")


def _is_union_type(tp: object) -> bool:
    """Return True if tp is a typing / PEP 604 union construct."""
    origin = get_origin(tp)
    if origin is Union:
        return True
    return origin is types.UnionType


_UNION_DISCRIMINATOR_KEYS: tuple[str, ...] = (
    "type",
    "pushEventType",
    "functionalChannelType",
    "channelRole",
)


def _literal_values(tp: object) -> set[object]:
    if get_origin(tp) is Literal:
        return set(get_args(tp))
    return set()


def _pick_typed_dict_union_variant(
    variants: tuple[object, ...], value: object
) -> object | None:
    if not isinstance(value, dict):
        return None
    best: object | None = None
    best_score = -10
    for variant in variants:
        if not _is_typed_dict(variant):
            continue
        ann = getattr(variant, "__annotations__", {})
        score = 0
        matched = False
        for key in _UNION_DISCRIMINATOR_KEYS:
            if key in value and key in ann:
                tp = ann[key]
                lits = _literal_values(tp)
                # Literal discriminator = strongest signal
                if lits:
                    if value[key] in lits:
                        score += 50
                        matched = True
                    else:
                        # Hard mismatch -> invalidate this variant completely
                        score = -100
                        matched = False
                        break
                else:
                    # Non-literal discriminator: soft signal if runtime value type matches annotation base
                    base = _unwrap_optional(tp)
                    try:
                        if isinstance(base, type) and isinstance(value[key], base):
                            score += 5
                            matched = True
                        else:
                            score += 1  # weak hint due to key presence
                    except TypeError:
                        score += 1
        if score < 0:
            continue
        required_keys = set(getattr(variant, "__annotations__", {}).keys())
        present = required_keys.intersection(value.keys())
        missing = required_keys - value.keys()
        score += len(present) * 0.05
        score -= len(missing) * 0.02
        if matched and score > best_score:
            best_score = score
            best = variant
    return best


def _variant_literal_mismatch(variant: object, value: object) -> bool:
    """Return True if any literal discriminator key on variant mismatches value.

    Only considers keys in _UNION_DISCRIMINATOR_KEYS that are annotated as Literal[...] on the variant.
    Missing discriminator key on value is treated as mismatch (can't positively identify variant).
    """
    if not isinstance(value, dict) or not _is_typed_dict(variant):
        return True
    ann = getattr(variant, "__annotations__", {})
    for key in _UNION_DISCRIMINATOR_KEYS:
        if key not in ann:
            continue
        tp = ann[key]
        if get_origin(tp) is Literal:
            lits = set(get_args(tp))
            if key not in value:
                return True
            if value[key] not in lits:
                return True
    return False


def _validate_value(path: str, tp: object, value: object, issues: list[str]) -> None:
    origin = get_origin(tp)
    if origin is None:
        # Simple type or TypedDict
        if _is_typed_dict(tp):
            _validate_typed_dict(path, tp, value, issues)
        else:
            try:
                if (tp is None and (value is not None)) or (not isinstance(value, tp)):  # type: ignore[arg-type]
                    issues.append(
                        f"{path}: expected {getattr(tp, '__name__', tp)}, got {type(value).__name__}"
                    )
            except TypeError:
                # TypedDict or non-instantiable target; treat as non-fatal
                pass
    elif origin is dict:
        if not isinstance(value, dict):
            issues.append(f"{path}: expected dict, got {type(value).__name__}")
    elif origin is list:
        if not isinstance(value, list):
            issues.append(f"{path}: expected list, got {type(value).__name__}")
        else:
            (elem_type,) = get_args(tp) or (Any,)
            for i, elem in enumerate(value):
                _validate_value(f"{path}[{i}]", elem_type, elem, issues)
    elif origin is tuple:
        args = get_args(tp)
        if not isinstance(value, tuple):
            issues.append(f"{path}: expected tuple, got {type(value).__name__}")
        else:
            for i, (elem, elem_type) in enumerate(zip(value, args)):
                _validate_value(f"{path}[{i}]", elem_type, elem, issues)
    elif origin is set:
        if not isinstance(value, set):
            issues.append(f"{path}: expected set, got {type(value).__name__}")
    elif origin is types.UnionType or _is_union_type(tp):  # union (typing | PEP604)
        variants = get_args(tp)
        matched = False
        for v in variants:
            # TypedDict variant: match if value is a dict
            if _is_typed_dict(v):
                if isinstance(value, dict):
                    matched = True
                    break
                continue
            # Simple class type
            if isinstance(v, type):
                if isinstance(value, v):
                    matched = True
                    break
                continue
            # Fallback: accept (cannot precisely check at runtime)
            matched = True
            break
        if not matched:
            issues.append(
                f"{path}: value {value!r} not compatible with union variants (count={len(variants)})"
            )


P = ParamSpec("P")
R = TypeVar("R")


def _unwrap_optional(tp: Any) -> Any:  # pyright: ignore[reportExplicitAny, reportAny]
    """Return the inner type for Optional / PEP 604 union with None.

    Supports both typing.Optional[T] / Union[T, None] and PEP 604 syntax (T | None).
    If multiple non-None members remain (e.g. int | str | None) we keep the
    original union because it isn't a simple Optional.
    """
    try:
        if _is_union_type(tp):
            args = get_args(tp)
            non_none = tuple(a for a in args if a is not type(None))  # noqa: E721
            if len(non_none) == 1:
                return non_none[0]
    except Exception:  # pragma: no cover - defensive
        pass
    return tp


def _is_any(tp: Any) -> bool:  # pyright: ignore[reportExplicitAny, reportAny]
    try:
        return tp is Any or getattr(tp, "__origin__", None) is Any
    except Exception:  # pragma: no cover - defensive
        return False


def _validate_literal(tp: Any, value: Any) -> bool:  # pyright: ignore[reportExplicitAny, reportAny]
    if get_origin(tp) is Literal:
        # if value not in get_args(tp):
        #    print(
        #        "value",
        #        value,
        #        "get_origin",
        #        get_origin(tp),
        #        "get_args",
        #        get_args(tp),
        #        "tp",
        #        tp,
        #    )
        return value in get_args(tp)
    return True


def _validate_generic(
    origin: Any,  # pyright: ignore[reportExplicitAny, reportAny]
    args: tuple[Any, ...],  # pyright: ignore[reportExplicitAny]
    value: Any,  # pyright: ignore[reportExplicitAny, reportAny]
    path: str,
    issues: list[str],
    depth: int,
) -> None:
    if origin in (list, tuple, set):
        if not isinstance(value, origin):
            issues.append(
                f"{path}: expected {origin.__name__}, got {type(value).__name__}"
            )
            return
        elem_types: tuple[Any, ...]
        if not args:
            return
        if origin is tuple and len(args) != 2 and args and args[-1] is Ellipsis:
            # Homogenous tuple like Tuple[T, ...]
            elem_types = (args[0],)
        else:
            elem_types = args
        for i, elem in enumerate(value):  # pyright: ignore[reportUnknownVariableType]
            check_tp = elem_types[min(i, len(elem_types) - 1)]
            _runtime_type_check(check_tp, elem, f"{path}[{i}]", issues, depth + 1)
    elif origin is dict:
        if not isinstance(value, dict):
            issues.append(f"{path}: expected dict, got {type(value).__name__}")
            return
        if len(args) == 2:
            kt, vt = args
            for i, (k, v) in enumerate(value.items()):  # pyright: ignore[reportUnknownVariableType]
                if i >= 50:  # limit to avoid huge cost
                    break
                _runtime_type_check(kt, k, f"{path}.<key>", issues, depth + 1)
                _runtime_type_check(vt, v, f"{path}[{repr(k)}]", issues, depth + 1)
    else:
        # Fallback: basic instance check
        if not isinstance(value, origin):
            issues.append(
                f"{path}: expected {getattr(origin, '__name__', origin)}, got {type(value).__name__}"
            )


def _runtime_type_check(
    tp: Any,
    value: Any,
    path: str,
    issues: list[str],
    depth: int = 0,
    max_depth: int = 6,
) -> None:
    if depth > max_depth:
        return
    if _is_any(tp):  # Any accepts everything
        return
    if tp is object:
        return
    # Fast-path: accept None when annotation explicitly allows it (before Optional unwrapping).
    # Without this guard, we unwrap Optional[T] to T and then incorrectly flag None values.
    if value is None:
        try:
            if tp is None or tp is type(None):  # direct None annotation
                return
            if _is_union_type(tp):
                args = get_args(tp)
                # If any variant is exactly NoneType we accept None immediately
                if any(a is type(None) for a in args):  # noqa: E721
                    return
        except Exception:  # pragma: no cover - defensive
            pass
    # Handle optionals
    base = _unwrap_optional(tp)
    origin = get_origin(base)
    # Early guard: if 'base' is not a type / TypedDict / union / literal container we skip.
    if not (
        isinstance(base, type)
        or _is_typed_dict(base)
        or _is_union_type(base)
        or origin is not None
        or base is None
    ):
        # Prevent messages like 'expected UnionType, got dict' when a runtime value
        # (e.g. already a dict) was accidentally passed as the spec.
        return
    if origin is Literal:
        if not _validate_literal(tp, value):
            issues.append(f"{path}: value {value!r} not in {get_args(base)!r}")
        return
    if _is_typed_dict(base):
        try:
            _validate_typed_dict(path, base, value, issues)
        except KeyError as ke:
            issues.append(str(ke))
        return
    if _is_union_type(base):  # handle Union / PEP604
        union_args = get_args(base)
        # Fast discriminant-based selection for TypedDict unions
        chosen = _pick_typed_dict_union_variant(union_args, value)
        if chosen is not None:
            _runtime_type_check(chosen, value, path, issues, depth + 1, max_depth)
            return
        # Fallback: sequential attempt until one yields no new issues
        best_variant: object | None = None
        best_variant_missing = 10**9
        # Track whether any variant matched strictly (zero issues) for early exit
        for variant in union_args:  # type: ignore[reportExplicitAny]
            # Skip early if literal discriminator mismatch
            if _is_typed_dict(variant) and isinstance(value, dict):  # type: ignore[reportExplicitAny]
                try:
                    if _variant_literal_mismatch(variant, value):
                        continue
                except Exception:
                    # defensive: skip on unexpected errors
                    continue
            trial_issues: list[str] = []
            if _is_typed_dict(variant) and isinstance(value, dict):  # type: ignore[reportExplicitAny]
                # Probe with allow_extra to focus on missing keys first
                try:
                    _validate_typed_dict(
                        path,
                        variant,
                        value,
                        trial_issues,
                        allow_extra=True,
                        record_unexpected=False,
                    )  # type: ignore[reportExplicitAny]
                except KeyError:
                    # Should not raise with allow_extra=True, but ignore if it does
                    pass
                missing_count = sum(
                    1 for m in trial_issues if m.endswith("missing key")
                )
                if missing_count < best_variant_missing:
                    best_variant_missing = missing_count
                    best_variant = variant
                if missing_count == 0:
                    # Re-run strictly to record any unexpected keys / nested issues
                    strict_issues: list[str] = []
                    try:
                        _validate_typed_dict(
                            path,
                            variant,
                            value,
                            strict_issues,
                            allow_extra=False,
                            record_unexpected=True,
                        )  # type: ignore[reportExplicitAny]
                    except KeyError as ke:
                        strict_issues.append(str(ke))
                    issues.extend(strict_issues)
                    return
            else:
                _runtime_type_check(
                    variant, value, path, trial_issues, depth + 1, max_depth
                )  # type: ignore[reportExplicitAny]
                if not trial_issues:
                    return

        # No variant matched perfectly. Produce detailed diagnostics explaining why.
        def _variant_name(v: object) -> str:
            return getattr(v, "__name__", repr(v))

        if isinstance(value, dict):
            diagnostics: list[str] = []
            MAX_VARIANTS = 12
            shown = 0
            for variant in union_args:  # type: ignore[reportExplicitAny]
                if shown >= MAX_VARIANTS:
                    diagnostics.append(
                        f"... ({len(union_args) - shown} more variants omitted)"
                    )
                    break
                if not _is_typed_dict(variant):  # type: ignore[reportExplicitAny]
                    continue
                shown += 1
                v_issues: list[str] = []
                try:
                    _validate_typed_dict(
                        path,
                        variant,
                        value,
                        v_issues,
                        allow_extra=False,
                        record_unexpected=True,
                    )  # type: ignore[reportExplicitAny]
                except KeyError as ke:
                    v_issues.append(str(ke))
                missing: list[str] = []
                unexpected: list[str] = []
                nested: list[str] = []
                for msg in v_issues:
                    if msg.endswith("missing key"):
                        comp = msg.split(":", 1)[0].removeprefix(f"{path}.")
                        missing.append(comp)
                    elif msg.endswith("unexpected key"):
                        comp = msg.split(":", 1)[0].removeprefix(f"{path}.")
                        unexpected.append(comp)
                    else:
                        nested.append(msg)
                literal_mismatches: list[str] = []
                ann = getattr(variant, "__annotations__", {})  # type: ignore[reportExplicitAny]
                for k in _UNION_DISCRIMINATOR_KEYS:
                    if k in ann and get_origin(ann[k]) is Literal:  # type: ignore[reportExplicitAny]
                        allowed = set(get_args(ann[k]))
                        if k not in value:
                            literal_mismatches.append(
                                f"{k}=<missing> expected one of {sorted(allowed)!r}"
                            )
                        elif value[k] not in allowed:
                            literal_mismatches.append(
                                f"{k}={value[k]!r} not in {sorted(allowed)!r}"
                            )
                parts: list[str] = []
                if missing:
                    parts.append(f"missing={missing}")
                if unexpected:
                    parts.append(f"unexpected={unexpected}")
                if literal_mismatches:
                    parts.append(f"literal={literal_mismatches}")
                if nested and len(nested) < 4:
                    parts.append(f"nested={nested}")
                elif nested:
                    parts.append(f"nestedIssues={len(nested)}")
                if not parts:
                    parts.append("(no direct key issues – likely nested mismatch)")
                diagnostics.append(f"{_variant_name(variant)} -> " + ", ".join(parts))  # type: ignore[reportExplicitAny]
            if best_variant is not None:
                best_name = _variant_name(best_variant)
                diagnostics.sort(
                    key=lambda d: 0 if d.startswith(best_name + " ->") else 1
                )
            issues.append(
                f"{path}: dict not compatible with any of {len(union_args)} union variants. Details: "
                + " | ".join(diagnostics)
            )
            return
        else:
            issues.append(
                f"{path}: value {type(value).__name__} not compatible with any union variant ({len(union_args)})"
            )
        return
    if origin is not None:
        _validate_generic(origin, get_args(base), value, path, issues, depth)
        return
    # Primitive / class check
    if base is None:
        if value is not None:
            issues.append(f"{path}: expected None, got {type(value).__name__}")
        return
    if not isinstance(value, base):
        # Improve union residual case readability (should rarely happen)
        if _is_union_type(base):
            issues.append(f"{path}: value {value!r} not in union {get_args(base)!r}")
        else:
            issues.append(
                f"{path}: expected {getattr(base, '__name__', base)}, got {type(value).__name__}"
            )


def _quick_match(tp: Any, value: Any) -> bool:  # pyright: ignore[reportExplicitAny, reportAny]
    """Fast, shallow compatibility check used during Union / overload filtering."""
    try:
        if _is_any(tp) or tp is object:
            return True
        base = _unwrap_optional(tp)
        origin = get_origin(base)
        if origin is Literal:
            return value in get_args(base)
        if _is_typed_dict(base):
            return isinstance(value, dict)
        if _is_union_type(base):
            return any(_quick_match(a, value) for a in get_args(base))
        if origin in (list, tuple, set):
            return isinstance(value, origin)
        if origin is dict:
            return isinstance(value, dict)
        if base is None:
            return value is None
        try:
            return isinstance(value, base)
        except TypeError:
            return False
    except Exception:
        return True  # Be permissive on unexpected forms


def _format_issues(label: str, issues: list[str], duration: float) -> None:
    for msg in issues:
        warnings.warn(f"{label}: {msg}")
    if issues:
        logging.getLogger("type_checker").debug(
            "%s: %d issue(s) validated in %.4fs", label, len(issues), duration
        )


TYPE_CHECKING_ENABLED = True


def type_checker(func: Callable[P, R]) -> Callable[P, R]:
    """Universal runtime type checker decorator with overload support.

    Features:
    - Resolves which overload (if any) matches the provided runtime arguments.
    - Validates annotated argument types (except *args/**kwargs contents) for the
      selected overload (or the implementation as a fallback).
    - Validates the return type (including nested containers & TypedDicts).
    - Gracefully degrades on unsupported / complex typing constructs (skips).
    - Bounded recursion depth to avoid excessive cost.
    - Designed to work on bound methods (ignores 'self' / 'cls').
    """
    import inspect
    from typing import get_overloads

    logger = logging.getLogger("type_checker")

    try:
        overload_defs = list(get_overloads(func))  # type: ignore[arg-type]
    except Exception:  # pragma: no cover - defensive
        overload_defs = []

    # Precompute metadata for overloads
    overload_meta: list[tuple[inspect.Signature, dict[str, Any]]] = []  # pyright: ignore[reportExplicitAny]
    for ov in overload_defs:
        try:
            sig = inspect.signature(ov)
            hints = get_type_hints(ov)  # type: ignore[arg-type]
            overload_meta.append((sig, hints))
        except Exception:  # pragma: no cover - skip malformed
            continue

    impl_sig = None
    try:
        impl_sig = inspect.signature(func)
    except Exception:  # pragma: no cover
        pass
    impl_hints: dict[str, Any] = {}  # pyright: ignore[reportExplicitAny]
    try:
        impl_hints = get_type_hints(func)  # type: ignore[arg-type]
    except Exception:  # pragma: no cover
        pass

    def _select_overload(
        call_args: tuple[Any, ...], call_kwargs: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:  # pyright: ignore[reportExplicitAny]
        if not overload_meta or impl_sig is None:
            return impl_hints, {}
        matches: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
        for idx, (sig, hints) in enumerate(overload_meta):
            try:
                bound = sig.bind_partial(*call_args, **call_kwargs)
            except TypeError:
                continue
            # Build mapping excluding self/cls
            param_issues: list[str] = []
            for name, val in bound.arguments.items():
                if name in ("self", "cls"):
                    continue
                ann = hints.get(name)
                if ann is None:
                    continue
                if not _quick_match(ann, val):
                    param_issues.append(name)
                    break
            if not param_issues:
                matches.append((idx, hints, dict(bound.arguments)))
        if not matches:
            return impl_hints, {}
        # Pick first (defined order) match
        _idx, hints, bargs = matches[0]
        return hints, bargs

    @functools.wraps(func)
    def wrapper(*call_args: P.args, **call_kwargs: P.kwargs) -> R:
        if not TYPE_CHECKING_ENABLED:
            return func(*call_args, **call_kwargs)
        selected_hints, bound_args = _select_overload(call_args, call_kwargs)
        # Validate arguments
        arg_issues: list[str] = []
        start = time.perf_counter()
        for name, ann in selected_hints.items():
            if name == "return":
                continue
            if name in ("self", "cls"):
                continue
            if name in bound_args:
                _runtime_type_check(
                    ann, bound_args[name], f"param '{name}'", arg_issues
                )
        arg_duration = time.perf_counter() - start
        _format_issues(f"{func.__name__} arguments", arg_issues, arg_duration)
        result = func(*call_args, **call_kwargs)
        # Validate return
        if "return" in selected_hints and result is not None:
            ret_ann = selected_hints["return"]
            ret_issues: list[str] = []
            rstart = time.perf_counter()
            _runtime_type_check(ret_ann, result, "return", ret_issues)
            rdur = time.perf_counter() - rstart
            if ret_issues:
                print(result)
            _format_issues(f"{func.__name__} return", ret_issues, rdur)
        return result

    logger.debug(
        "type_checker applied to %s with %d overload(s)",
        getattr(func, "__qualname__", func),
        len(overload_meta),
    )
    return wrapper


def validate_annotated(
    value: object,
    name: str | None = None,
    *,
    raise_on_error: bool = False,
    max_depth: int = 6,
) -> list[str]:
    """Validate a variable against its annotated type in the caller's function.

    Usage inside a function or method with annotated parameters:
        def f(data: MyTypedDict):
            validate_annotated(data)   # picks 'data' automatically

    You can also specify the parameter name explicitly:
        validate_annotated(data, name='data')

    Returns a list of issue strings. If raise_on_error=True, raises TypeError
    if any issues are found. Best-effort: if the function or annotation can't
    be resolved, it returns an empty list silently.
    """
    try:
        frame = inspect.currentframe()
        if frame is None or frame.f_back is None:  # pragma: no cover - defensive
            return []
        caller = frame.f_back
        code = caller.f_code
        locs = caller.f_locals
        globs = caller.f_globals

        # Attempt to locate the callable object for better get_type_hints handling
        func_obj: object | None = None

        # Method: search on self / cls first
        self_obj = locs.get("self") or locs.get("cls")
        if self_obj is not None:
            for attr_name in dir(self_obj):
                try:
                    attr = getattr(self_obj, attr_name)
                except Exception:  # pragma: no cover
                    continue
                if callable(attr) and getattr(attr, "__code__", None) is code:
                    func_obj = attr
                    break
        # Fallback: scan globals
        if func_obj is None:
            for gval in globs.values():
                if callable(gval) and getattr(gval, "__code__", None) is code:
                    func_obj = gval
                    break
        if func_obj is None:
            return []  # Can't resolve function

        try:
            hints = get_type_hints(func_obj)  # type: ignore[arg-type]
        except Exception:
            return []

        # Infer parameter name if not explicitly provided
        target_name: str | None = name
        if target_name is None:
            for var_name, var_val in locs.items():
                if id(var_val) == id(value) and var_name in hints:
                    target_name = var_name
                    break
        if target_name is None:
            return []  # No matching annotated name

        expected = hints.get(target_name)
        if expected is None:
            return []
        issues: list[str] = []
        _runtime_type_check(expected, value, target_name, issues, 0, max_depth)
        if issues:
            for msg in issues:
                warnings.warn(f"validate_annotated: {msg}")
            if raise_on_error:
                raise TypeError(
                    f"{target_name} failed runtime validation with {len(issues)} issue(s): {issues[:3]}..."
                )
        return issues
    finally:
        try:
            del frame  # pyright: ignore[reportPossiblyUnboundVariable]
        except Exception:
            pass


class HCUController:
    """Home Control Unit Controller"""

    plugin_id: str = "com.homeassistant.custom"
    logger: logging.Logger = logging.getLogger("HCUController")
    # Cached system state body returned from getSystemState
    _system_state: SystemState | None
    _state_lock: threading.Lock
    _listeners: list[Callable[[], None]]
    first_connection: bool = True

    def __init__(self, ip: str, activation_key: str, auth_token: str, client_id: str):
        self.logger.setLevel(logging.INFO)
        self.ip: str = ip
        self.activation_key: str = activation_key
        self.auth_token: str = auth_token
        self.client_id: str = client_id
        # Pending requests: id -> { expected_type: str, event: threading.Event, response: dict|None }
        self._pending_lock: threading.Lock = threading.Lock()
        self._pending: PendingMap = {}
        websocket_headers = {
            "authtoken": auth_token,
            "plugin-id": self.plugin_id,
            "hmip-system-events": "true",
        }
        self.ws: WebSocketApp = WebSocketApp(
            f"wss://{self.ip}:9001", header=websocket_headers
        )

        self.ws.on_message = self._ws_message_handler
        self.ws.on_error = self._ws_error_handler
        self.ws.on_close = self._ws_close_handler
        self.ws.on_open = self._ws_open_handler
        # Runtime state
        self._ws_thread: threading.Thread | None = None
        self._ws_open_event: threading.Event = threading.Event()
        self._system_state = None
        self._state_lock = threading.Lock()
        self._listeners = []

    def add_state_listener(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register a listener invoked when cached system state changes.

        Returns a remover callable.
        """
        self._listeners.append(callback)

        def _remove() -> None:
            try:
                self._listeners.remove(callback)
            except ValueError:
                pass

        return _remove

    def _notify_state_listeners(self) -> None:
        for cb in list(self._listeners):
            try:
                cb()
            except Exception:
                self.logger.exception("State listener failed")

    def start(self) -> None:
        """Start websocket processing in background thread."""
        if self._ws_thread and self._ws_thread.is_alive():
            return

        def _run() -> None:
            backoff: float = 1.0
            max_backoff: float = 30.0
            while True:
                _ok: bool = self.ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})  # pyright: ignore[reportUnknownMemberType]
                if _ok is True:
                    delay = min(backoff, max_backoff)
                    self.logger.warning(
                        "WebSocket will attempt reconnect in %.1fs", delay
                    )
                    time.sleep(delay)
                    backoff = min(backoff * 2.0, max_backoff)
                    continue
                break

        self._ws_thread = threading.Thread(target=_run, name="hcu-ws", daemon=True)
        self._ws_thread.start()

    def stop(self) -> None:
        """Stop websocket processing."""
        try:
            self.ws.close()  # pyright: ignore[reportUnknownMemberType]
        except Exception:
            pass

    def _send_plugin_message(
        self,
        msg_id: str,
        msg_type: str,
        body: dict[str, Any] | None = None,  # pyright: ignore[reportExplicitAny]
    ) -> None:
        data: dict[str, str | dict[str, Any]] = {  # pyright: ignore[reportExplicitAny]
            "pluginId": self.plugin_id,
            "id": msg_id,
            "type": msg_type,
        }
        if body:
            data["body"] = body
        self.ws.send(json.dumps(data))

    def _ws_error_handler(self, ws: WebSocket, err: str) -> None:  # pyright: ignore[reportUnusedParameter]
        self.logger.error("WebSocket error: %s", err)

    def _ws_close_handler(self, ws: WebSocket, code: str, msg: str) -> None:  # pyright: ignore[reportUnusedParameter]
        self.logger.info("WebSocket closed with code: %d, message: %s", code, msg)

    def _send_plugin_state_response(self, msg_id: str | None = None) -> None:
        if msg_id is None:
            msg_id = str(uuid.uuid4())
        body = {
            "pluginReadinessStatus": "READY",
            "friendlyName": {
                "de": "Home Assistant Custom Plugin",
                "en": "Home Assistant Custom Plugin",
            },
        }
        self._send_plugin_message(msg_id, "PLUGIN_STATE_RESPONSE", body)

    def _handle_plugin_state_request(self, msg_id: str, body: None) -> None:  # pyright: ignore[reportUnusedParameter]
        self._send_plugin_state_response(msg_id)

    def _send_discover_response(self, msg_id: str):
        self.logger.info("Sending discover response")
        body: dict[str, Any] = {  # pyright: ignore[reportExplicitAny]
            "devices": [],
            "success": True,
        }
        self._send_plugin_message(msg_id, "DISCOVER_RESPONSE", body)

    def _handle_discover_request(self, msg_id: str, body: None) -> None:  # pyright: ignore[reportUnusedParameter]
        self._send_discover_response(msg_id)

    def _send_request_message(
        self,
        msg_type: str,
        body: dict[str, Any],  # pyright: ignore[reportExplicitAny]
    ) -> dict[str, Any] | None:  # pyright: ignore[reportExplicitAny]
        msg_id = str(uuid.uuid4())
        expected_type = self._to_response_type(msg_type)
        evt = threading.Event()
        with self._pending_lock:
            self._pending[msg_id] = {
                "expected_type": expected_type,
                "event": evt,
                "response": None,
            }

        self.logger.info(
            "Sending request %s with id %s expecting %s",
            msg_type,
            msg_id,
            expected_type,
        )
        self._send_plugin_message(msg_id, msg_type, body)

        # Wait for matching response
        if not evt.wait(timeout=10):
            with self._pending_lock:
                _ = self._pending.pop(msg_id, None)
            raise TimeoutError(
                f"Timed out waiting for response to {msg_type} with id {msg_id}"
            )

        with self._pending_lock:
            entry = self._pending.pop(msg_id, None)
        if entry and "response" in entry:
            return entry["response"]["body"]  # pyright: ignore[reportUnknownVariableType, reportOptionalSubscript]
        return None

    def _handle_message_response(self, message: PluginMessage) -> None:
        msg_id = message.get("id")
        msg_type = message.get("type")
        plugin_id = message.get("pluginId")
        if not msg_id or not msg_type or not plugin_id:
            return
        if plugin_id != self.plugin_id:
            return
        with self._pending_lock:
            entry = self._pending.get(msg_id)
            if entry and message["body"]:
                expected_type = entry["expected_type"]
                body = message["body"]
                response = {"success": True, "body": body}
                if "error" in body or expected_type == "ERROR_RESPONSE":
                    response["success"] = False
                entry["response"] = response
                entry["event"].set()
                self.logger.debug("Matched response %s for id %s", msg_type, msg_id)
            else:
                # Not a pending request or type mismatch; ignore
                self.logger.error(
                    "Unmatched response: id=%s type=%s (pending=%s)",
                    msg_id,
                    msg_type,
                    bool(entry),
                )

    @staticmethod
    def _to_response_type(request_type: str) -> str:
        if request_type.endswith("_REQUEST"):
            return request_type[:-8] + "_RESPONSE"
        else:
            raise ValueError(f"Unknown request type: {request_type}")

    def _send_config_template_response(self, msg_id: str) -> None:
        self.logger.info("Sending config template response")
        body: dict[str, Any] = {"properties": {}}  # pyright: ignore[reportExplicitAny]
        self._send_plugin_message(msg_id, "CONFIG_TEMPLATE_RESPONSE", body)

    def _handle_config_template_request(
        self,
        msg_id: str,
        body: ConfigTemplateRequestBody,  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        self._send_config_template_response(msg_id)

    def _send_config_update_response(self, msg_id: str) -> None:
        self.logger.info("Sending config template response")
        body = {"status": "APPLIED"}
        self._send_plugin_message(msg_id, "CONFIG_UPDATE_RESPONSE", body)

    def _handle_config_update_request(
        self,
        msg_id: str,
        body: ConfigUpdateRequestBody,  # pyright: ignore[reportUnusedParameter]
    ) -> None:
        self._send_config_update_response(msg_id)

    def _plugin_message_handler(self, ws: WebSocket, message: PluginMessage) -> None:  # pyright: ignore[reportUnusedParameter]
        message_body = message["body"]
        message_str = json.dumps(message)
        if len(message_str) > 150:
            message_str = ""
            if (
                isinstance(message_body, dict)
                and "code" in message_body
                and isinstance(message_body.get("body"), dict)
            ):
                inner = message_body.get("body")
                if inner:
                    message_str += f"keys: {list(inner.keys())}"
                else:
                    message_str += f"keys: {list(message_body.keys())}"
                message_str += f" code: {message_body.get('code')}"
            elif isinstance(message_body, dict):
                message_str += f"keys: {list(message_body.keys())}"
            else:
                message_str += "body: None"
        else:
            message_str = message_body
        plugin_str = ""
        if message["pluginId"] != self.plugin_id:
            plugin_str = f', pluginId: "{message["pluginId"]}"'
        self.logger.info(
            'Plugin message received: id: "%s", type: "%s"%s, body: "%s"',
            message["id"],
            message["type"],
            plugin_str,
            message_str,
        )
        if message["type"] == "PLUGIN_STATE_REQUEST":
            self._handle_plugin_state_request(message["id"], message["body"])
        elif message["type"] == "DISCOVER_REQUEST":
            self._handle_discover_request(message["id"], message["body"])
        elif message["type"] == "CONFIG_TEMPLATE_REQUEST":
            self._handle_config_template_request(message["id"], message["body"])
        elif message["type"] == "CONFIG_UPDATE_REQUEST":
            self._handle_config_update_request(message["id"], message["body"])
        elif message["type"].lower().endswith("response"):
            self._handle_message_response(message)
        elif message["type"].lower().endswith("event"):
            self._handle_system_event(message)
        else:
            self.logger.warning(
                "Unknown plugin message type: %s body=%s", message["type"], message
            )

    # Overloads mapping each path to its corresponding request body type
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.getSystemState],
        body: HomeRequestBodies.Empty,
    ) -> HmIPSystemGetSystemStateResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.getState],
        body: HomeRequestBodies.Empty,
    ) -> HmIPSystemGetStateResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.getStateForClient],
        body: HomeRequestBodies.Empty,
    ) -> HmIPSystemGetStateForClientResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeRequestPaths.checkAuthToken],
        body: HomeRequestBodies.Empty,
    ) -> HmIpSystemResponseBody: ...

    # Group Profile
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupProfileRequestPaths.setProfileMode],
        body: GroupProfileRequestBodies.SetProfileModeRequestBody,
    ) -> HmIpSystemResponseBody: ...

    # Role
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPRoleRequestPaths.enableSimpleRule],
        body: RoleRequestBodies.EnableSimpleRule,
    ) -> HmIpSystemResponseBody: ...

    # Home Heating
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsencePermanent],
        body: HomeRequestBodies.Empty,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsenceWithDuration],
        body: HomeHeatingRequestBodies.ActivateAbsenceWithDuration,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsenceWithFuturePeriod],
        body: HomeHeatingRequestBodies.ActivateAbsenceWithFuturePeriod,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateAbsenceWithPeriod],
        body: HomeHeatingRequestBodies.ActivateAbsenceWithPeriod,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateFutureVacation],
        body: HomeHeatingRequestBodies.ActivateFutureVacation,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.activateVacation],
        body: HomeHeatingRequestBodies.ActivateVacation,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.deactivateAbsence],
        body: Mapping[str, object],
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.deactivateVacation],
        body: Mapping[str, object],
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeHeatingRequestPaths.setCooling],
        body: HomeHeatingRequestBodies.SetCooling,
    ) -> HmIpSystemResponseBody: ...

    # Group Heating
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.activatePartyMode],
        body: GroupHeatingRequestBodies.HmIPActivatePartyMode,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setActiveProfile],
        body: GroupHeatingRequestBodies.HmIPSetActiveProfile,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setBoost],
        body: GroupHeatingRequestBodies.HmIPSetBoost,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setControlMode],
        body: GroupHeatingRequestBodies.HmIPSetControlMode,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setHotWaterOnTime],
        body: GroupHeatingRequestBodies.HmIPSetHotWaterOnTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setHotWaterProfileMode],
        body: GroupHeatingRequestBodies.HmIPSetHotWaterProfileMode,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setHotWaterState],
        body: GroupHeatingRequestBodies.HmIPSetHotWaterState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupHeatingRequestPaths.setSetPointTemperature],
        body: GroupHeatingRequestBodies.HmIPSetPointTemperature,
    ) -> HmIpSystemResponseBody: ...

    # Home Security
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeSecurityRequestPaths.setExtendedZonesActivation],
        body: HomeSecurityRequestBodies.SetExtendedZonesActivation,
    ) -> HmIPSystemSetExtendedZonesActivationResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeSecurityRequestPaths.setZonesActivation],
        body: HomeSecurityRequestBodies.SetZonesActivation,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPHomeSecurityRequestPaths.acknowledgeSafetyAlarm],
        body: Mapping[str, object],
    ) -> HmIpSystemResponseBody: ...

    # Group Linked Control
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setOpticalSignalBehaviour
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetOpticalSignalBehaviour,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setSoundFileVolumeLevel],
        body: GroupLinkedControlRequestBodies.SetSoundFileVolumeLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setVentilationLevel],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setVentilationLevelWithTime
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setVentilationState],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setVentilationStateWithTime
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetVentilationStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.setWateringSwitchState],
        body: GroupLinkedControlRequestBodies.HmIPSetWateringSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupLinkedControlRequestPaths.setWateringSwitchStateWithTime
        ],
        body: GroupLinkedControlRequestBodies.HmIPSetWateringSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.startNotification],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.stopNotification],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.toggleVentilationState],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupLinkedControlRequestPaths.toggleWateringState],
        body: GroupLinkedControlRequestBodies.GroupId,
    ) -> HmIpSystemResponseBody: ...

    # Group Switching
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setColorTemperatureDimLevel],
        body: GroupSwitchingRequestBodies.SetColorTemperatureDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupSwitchingRequestPaths.setColorTemperatureDimLevelWithTime
        ],
        body: GroupSwitchingRequestBodies.SetColorTemperatureDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setDimLevel],
        body: GroupSwitchingRequestBodies.SetDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setDimLevelWithTime],
        body: GroupSwitchingRequestBodies.SetDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setFavoriteShadingPosition],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setHueSaturationDimLevel],
        body: GroupSwitchingRequestBodies.SetHueSaturationDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPGroupSwitchingRequestPaths.setHueSaturationDimLevelWithTime
        ],
        body: GroupSwitchingRequestBodies.SetHueSaturationDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setPrimaryShadingLevel],
        body: GroupSwitchingRequestBodies.SetPrimaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setSecondaryShadingLevel],
        body: GroupSwitchingRequestBodies.SetSecondaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setState],
        body: GroupSwitchingRequestBodies.SetSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.setSwitchStateWithTime],
        body: GroupSwitchingRequestBodies.SetSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.startLightScene],
        body: GroupSwitchingRequestBodies.StartLightScene,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.stop],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.toggleShadingState],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPGroupSwitchingRequestPaths.toggleSwitchState],
        body: GroupSwitchingRequestBodies.HmIPGroupsSwitching,
    ) -> HmIpSystemResponseBody: ...

    # Device Control
    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setDimLevel],
        body: DeviceControlRequestBodies.SetDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setDimLevelWithTime],
        body: DeviceControlRequestBodies.SetDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setColorTemperatureDimLevel],
        body: DeviceControlRequestBodies.SetColorTemperatureDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setColorTemperatureDimLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetColorTemperatureDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setHueSaturationDimLevel],
        body: DeviceControlRequestBodies.SetHueSaturationDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setHueSaturationDimLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetHueSaturationDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSwitchState],
        body: DeviceControlRequestBodies.SetSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSwitchStateForIdentify],
        body: DeviceControlRequestBodies.SetSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSwitchStateWithTime],
        body: DeviceControlRequestBodies.SetSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setDoorLockActive],
        body: DeviceControlRequestBodies.SetDoorLockActive,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setDoorLockActiveWithAuthorization
        ],
        body: DeviceControlRequestBodies.SetDoorLockActiveWithAuthorization,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setLockState],
        body: DeviceControlRequestBodies.SetLockState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setMotionDetectionActive],
        body: DeviceControlRequestBodies.SetMotionDetectionActive,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setOpticalSignal],
        body: DeviceControlRequestBodies.SetOpticalSignalBase,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setOpticalSignalWithTime],
        body: DeviceControlRequestBodies.SetOpticalSignalWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setPrimaryShadingLevel],
        body: DeviceControlRequestBodies.SetPrimaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSecondaryShadingLevel],
        body: DeviceControlRequestBodies.SetSecondaryShadingLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setShutterLevel],
        body: DeviceControlRequestBodies.SetShutterLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSimpleRGBColorDimLevel],
        body: DeviceControlRequestBodies.SetSimpleRGBColorDimLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setSimpleRGBColorDimLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetSimpleRGBColorDimLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSlatsLevel],
        body: DeviceControlRequestBodies.SetSlatsLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setSoundFileVolumeLevel],
        body: DeviceControlRequestBodies.SetSoundFileVolumeLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setSoundFileVolumeLevelWithTime
        ],
        body: DeviceControlRequestBodies.SetSoundFileVolumeLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationLevel],
        body: DeviceControlRequestBodies.SetVentilationLevel,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationLevelWithTime],
        body: DeviceControlRequestBodies.SetVentilationLevelWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationState],
        body: DeviceControlRequestBodies.SetVentilationState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setVentilationStateWithTime],
        body: DeviceControlRequestBodies.SetVentilationStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setWateringSwitchState],
        body: DeviceControlRequestBodies.SetWateringSwitchState,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.setWateringSwitchStateWithTime
        ],
        body: DeviceControlRequestBodies.SetWateringSwitchStateWithTime,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.startLightScene],
        body: DeviceControlRequestBodies.StartLightScene,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.sendDoorCommand],
        body: DeviceControlRequestBodies.SendDoorCommand,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.pullLatch],
        body: DeviceControlRequestBodies.PullLatch,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[
            HmIPDeviceControlRequestPaths.acknowledgeFrostProtectionError
        ],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetBlocking],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetEnergyCounter],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetPassageCounter],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.resetWaterVolume],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setFavoriteShadingPosition],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setIdentify],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.setIdentifyOem],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.startImpulse],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.stop],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleCameraNightVision],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleGarageDoorState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleShadingState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleSwitchState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleVentilationState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @overload
    def _send_hmip_system_request(
        self,
        hmip_path: Literal[HmIPDeviceControlRequestPaths.toggleWateringState],
        body: DeviceControlRequestBodies.HmIPDeviceControl,
    ) -> HmIpSystemResponseBody: ...

    @type_checker
    def _send_hmip_system_request(
        self, hmip_path: HmIPSystemRequestPaths, body: object
    ) -> HmIpSystemResponseBody:
        request_body: dict[str, Any] = {"path": hmip_path.value, "body": body}  # pyright: ignore[reportExplicitAny]
        self.logger.info(
            "Sending HMIP system request: path=%s, body=%s",
            hmip_path.value,
            body,
        )
        return cast(  # pyright: ignore[reportAny]
            Any,  # pyright: ignore[reportExplicitAny]
            self._send_request_message("HMIP_SYSTEM_REQUEST", request_body),
        )
        # home, groups, devices, clients
        # print(response["body"])

    def _handle_system_event(self, message: PluginMessage) -> None:
        if message["type"] == "HMIP_SYSTEM_EVENT":
            self._handle_hmip_system_event(message["body"])
        else:
            self.logger.warning(
                "Unknown system event type: %s message=%s", message["type"], message
            )

    def _handle_hmip_system_event(self, body: HmipSystemEventBody) -> None:
        # 1. Validate top-level body against its annotation
        summary_types = [
            ev["pushEventType"] for ev in body["eventTransaction"]["events"].values()
        ]
        self.logger.info("HMIP system event received (types=%s)", summary_types)
        try:
            issues = validate_annotated(body)
            if issues:
                unexpected = [i for i in issues if "unexpected key" in i]
                log_fn = self.logger.error if unexpected else self.logger.warning
                log_fn(
                    "HMIP system event body type issues (first %d): %s, body=%s",
                    min(10, len(issues)),
                    issues[:10],
                    body,
                )
                self.logger.info(body)
        except Exception:  # pragma: no cover - defensive
            self.logger.exception("validate_annotated failed for system event body")

        # 2. Log devices in this event that expose SINGLE_KEY_CHANNELs (warn level)
        try:
            events: dict[str, Event] = body["eventTransaction"].get("events", {})
            for ev in events.values():
                if ev["pushEventType"] != "DEVICE_CHANNEL_EVENT":
                    continue
                self.logger.warning("HMIP DEVICE_CHANNEL_EVENT: %s", ev)
        except Exception:
            self.logger.exception(
                "Failed to scan SINGLE_KEY_CHANNEL devices in system event"
            )

        # Merge incoming events into cached state and notify listeners
        try:
            with self._state_lock:
                if self._system_state is None:
                    return

                state = self._system_state

                def _get_map(key: str) -> dict[str, object]:
                    cur = state.get(key)
                    if not isinstance(cur, dict):
                        cur = {}
                        state[key] = cur
                    return cast(dict[str, object], cur)

                events = body["eventTransaction"]["events"]
                for ev_map in events.values():
                    if ev_map["pushEventType"] == "HOME_CHANGED":
                        state["home"] = ev_map["home"]
                    elif ev_map["pushEventType"] in ("DEVICE_ADDED", "DEVICE_CHANGED"):
                        dev = ev_map.get("device")
                        if isinstance(dev, dict):
                            did_obj = cast(dict[str, object], dev).get("id")
                            did = did_obj if isinstance(did_obj, str) else None
                            if did:
                                _get_map("devices")[did] = dev
                    elif ev_map["pushEventType"] == "DEVICE_REMOVED":
                        did_obj = ev_map["id"]
                        with self._state_lock:
                            _ = self._system_state["devices"].pop(did_obj, None)
                    elif ev_map["pushEventType"] in ("GROUP_ADDED", "GROUP_CHANGED"):
                        grp = ev_map.get("group")
                        if isinstance(grp, dict):
                            gid_obj = cast(dict[str, object], grp).get("id")
                            gid = gid_obj if isinstance(gid_obj, str) else None
                            if gid:
                                _get_map("groups")[gid] = grp
                    elif ev_map["pushEventType"] == "GROUP_REMOVED":
                        gid = ev_map.get("id")
                        if gid:
                            _ = _get_map("groups").pop(gid, None)
                    elif ev_map["pushEventType"] in ("CLIENT_ADDED", "CLIENT_CHANGED"):
                        cli = ev_map.get("client")
                        if isinstance(cli, dict):
                            cid_obj = cast(dict[str, object], cli).get("id")
                            cid = cid_obj if isinstance(cid_obj, str) else None
                            if cid:
                                _get_map("clients")[cid] = cli
                    elif ev_map["pushEventType"] == "CLIENT_REMOVED":
                        cid = ev_map.get("id")
                        if cid:
                            _ = _get_map("clients").pop(cid, None)
        except Exception:
            self.logger.exception("Failed merging HMIP system event into state")
        else:
            self._notify_state_listeners()

    def _ws_open_handler(self, ws: WebSocket) -> None:  # pyright: ignore[reportUnusedParameter]
        self.logger.info("WebSocket connection opened")
        self._ws_open_event.set()
        self._send_plugin_state_response()
        if not self.first_connection:
            self.first_connection = False
            threading.Thread(
                target=self._send_initial_hmip_system_request,
                name="hcu-request-worker",
                args=(),
                daemon=True,
            ).start()

    def _send_initial_hmip_system_request(self) -> None:
        """Send an initial system state fetch after WS open."""
        try:
            response = self._send_hmip_system_request(
                HmIPHomeRequestPaths.getSystemState, {}
            )
            self._system_state = response["body"]
        except Exception as exc:
            self.logger.exception("Initial HMIP request failed: %s", exc)
        else:
            self._notify_state_listeners()

    def wait_until_ready(self, timeout: float = 5.0) -> bool:
        """Block until websocket on_open fired."""
        return self._ws_open_event.wait(timeout)

    def get_system_state(self) -> SystemState:
        """Return cached system state if present; try to fetch if missing."""
        if self._system_state is None:
            resp = self._send_hmip_system_request(
                HmIPHomeRequestPaths.getSystemState, {}
            )
            self._system_state = resp["body"]
        return self._system_state

    def _ws_message_handler(self, ws: WebSocket, message: str) -> None:
        json_message = cast(PluginMessage, json.loads(message))
        if json_message["pluginId"] == self.plugin_id:
            self._plugin_message_handler(ws, json_message)
        else:
            self.logger.warning(
                "Unknown plugin message received: %s", json.dumps(json_message)
            )

    # ---- Public convenience API wrappers -------------------------------------------------
    def set_heating_group_setpoint(self, group_id: str, temperature: float) -> None:
        """Set target temperature on a heating group.

        This is a thin wrapper around the GroupHeating setSetPointTemperature request.
        """
        try:
            _ = self._send_hmip_system_request(
                HmIPGroupHeatingRequestPaths.setSetPointTemperature,
                {"groupId": group_id, "setPointTemperature": float(temperature)},
            )
        except Exception:
            self.logger.exception(
                "Failed to send setSetPointTemperature for group %s", group_id
            )

    def set_notification_light(
        self,
        device_id: str,
        channel_index: int,
        *,
        simple_rgb_color_state: str = "WHITE",
        optical_signal_behaviour: str = "ON",
        dim_level: float = 1.0,
    ) -> None:
        """Control Access Point notification light via setOpticalSignal.

        Params:
        - device_id: HCU device id (ACCESS_POINT)
        - channel_index: notification light channel index (usually 1)
        - simple_rgb_color_state: one of BLACK/BLUE/GREEN/TURQUOISE/RED/PURPLE/YELLOW/WHITE
        - optical_signal_behaviour: OFF/ON/BLINKING_MIDDLE/FLASH_MIDDLE/BILLOW_MIDDLE
        - dim_level: 0.0 .. 1.0
        """
        try:
            body: DeviceControlRequestBodies.SetOpticalSignalBase = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "simpleRGBColorState": str(simple_rgb_color_state),
                "opticalSignalBehaviour": str(optical_signal_behaviour),
                "dimLevel": float(dim_level),
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setOpticalSignal,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to control notification light for device %s ch %s",
                device_id,
                channel_index,
            )

    def set_dimmer_level(
        self, device_id: str, channel_index: int, *, dim_level: float
    ) -> None:
        """Set dim level (0.0..1.0) on a DIMMER_CHANNEL.

        Uses the Device Control setDimLevel endpoint. Note: the type schema in
        hmip_device_control annotates dimLevel as int, but HmIP expects a
        fractional level between 0.0 and 1.0. We pass float; the runtime
        validator may warn but the device accepts it.
        """
        try:
            body: DeviceControlRequestBodies.SetDimLevel = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "dimLevel": dim_level,
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setDimLevel,
                body,
            )
            self.logger.error(
                "Set dim level for device %s ch %s -> %s, %s",
                device_id,
                channel_index,
                dim_level,
                _,
            )
        except Exception:
            self.logger.exception(
                "Failed to set dim level for device %s ch %s -> %s",
                device_id,
                channel_index,
                dim_level,
            )

    def set_switch_state(self, device_id: str, channel_index: int, *, on: bool) -> None:
        """Set switch state on a SWITCH_CHANNEL via setSwitchState."""
        try:
            body: DeviceControlRequestBodies.SetSwitchState = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "on": bool(on),
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setSwitchState,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to set switch state for device %s ch %s -> %s",
                device_id,
                channel_index,
                on,
            )

    def set_hue_saturation_dim_level(
        self,
        device_id: str,
        channel_index: int,
        *,
        hue: int,
        saturation_level: float,
        dim_level: float,
    ) -> None:
        """Set HS + brightness on a UNIVERSAL_LIGHT_CHANNEL using setHueSaturationDimLevel.

        hue: 0..359
        saturation_level: 0.0..1.0
        dim_level: 0.0..1.0
        """
        try:
            body: DeviceControlRequestBodies.SetHueSaturationDimLevel = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "hue": int(max(0, min(359, hue))),
                # schema types mark saturationLevel/dimLevel as int, but device expects float 0..1
                "saturationLevel": max(
                    0.0,
                    min(1.0, saturation_level),
                ),  # type: ignore[arg-type]
                "dimLevel": cast(int, float(max(0.0, min(1.0, dim_level)))),  # type: ignore[arg-type]
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setHueSaturationDimLevel,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to set HS for device %s ch %s (h=%s s=%s dim=%s)",
                device_id,
                channel_index,
                hue,
                saturation_level,
                dim_level,
            )

    def set_color_temperature_dim_level(
        self,
        device_id: str,
        channel_index: int,
        *,
        color_temperature: int,
        dim_level: float,
    ) -> None:
        """Set color temperature (Kelvin) + brightness on a UNIVERSAL_LIGHT_CHANNEL."""
        try:
            body: DeviceControlRequestBodies.SetColorTemperatureDimLevel = {
                "deviceId": device_id,
                "channelIndex": int(channel_index),
                "colorTemperature": int(color_temperature),
                "dimLevel": cast(int, float(max(0.0, min(1.0, dim_level)))),  # type: ignore[arg-type]
            }
            _ = self._send_hmip_system_request(
                HmIPDeviceControlRequestPaths.setColorTemperatureDimLevel,
                body,
            )
        except Exception:
            self.logger.exception(
                "Failed to set CT for device %s ch %s (K=%s dim=%s)",
                device_id,
                channel_index,
                color_temperature,
                dim_level,
            )


# activation_key = "198345"
## init_data = init_hcu_plugin("192.168.178.165", activation_key)
## auth_token = "C909C35DAA0E1FFC0DB2CC29DE3D8787595681515F12B3B6968AF8A74337B275"
## print("init_data", init_data)
# init_data = {
#    "auth_token": "C909C35DAA0E1FFC0DB2CC29DE3D8787595681515F12B3B6968AF8A74337B275",
#    "client_id": "130fd270-8222-41bb-a169-1504662b34ef",
# }
# hcu = HCUController(
#    "192.168.178.165", activation_key, init_data["auth_token"], init_data["client_id"]
# )
