from src.decoders import ALL_DECODERS, decode_caesar
from src.detector import compute_score
from src.models import DecodeResult
from src.policy import get_transition_policy, _is_base64_like


def _get_method_name(decoder) -> str:
    name = decoder.__name__.replace("decode_", "").upper()
    if name == "BYTES_LITERAL":
        return "BYTES_LITERAL_EXTRACT"
    return name


DECODER_BY_NAME = {
    "BASE64": None,
    "HEX": None,
    "BINARY": None,
    "ASCII_DECIMAL": None,
    "A1Z26": None,
    "ROT13": None,
    "REVERSE": None,
    "URL_DECODE": None,
    "BYTES_LITERAL_EXTRACT": None,
}
for d in ALL_DECODERS:
    name = _get_method_name(d)
    if name in DECODER_BY_NAME:
        DECODER_BY_NAME[name] = d


def _score_result(result: DecodeResult, previous_input: str = None) -> None:
    score, flags, confidence = compute_score(result.output, previous_input, result.chain)
    result.score = score
    result.flags = flags
    result.confidence = confidence


def _should_expand(result: DecodeResult, current_text: str) -> bool:
    if result.status != "success" or not result.output:
        return False
    if result.output == current_text:
        return False
    if len(result.output) < 4 or len(result.output) > 5000:
        return False
    if result.confidence == "NOISE":
        return False
    if result.flags:
        return False
    return True


def _has_reverse_in_chain(chain: list[str]) -> bool:
    """Check if chain contains REVERSE decoder."""
    return "REVERSE" in chain


def _is_noise_family_result(result: DecodeResult, all_results: list[DecodeResult]) -> bool:
    """Check if result belongs to a noise family (e.g., BASE64 -> CAESAR_SHIFT_n)."""
    if not result.chain or len(result.chain) < 2:
        return False
    if not result.chain[-1].startswith("CAESAR_SHIFT_"):
        return False
    parent_chain = result.chain[:-1]
    same_parent_count = sum(
        1 for r in all_results
        if r.chain and r.chain[:-1] == parent_chain and r.chain[-1].startswith("CAESAR_SHIFT_")
    )
    return same_parent_count >= 3


def _apply_reverse_penalty(result: DecodeResult) -> DecodeResult:
    """Apply stronger penalty to low-value reverse-based chains."""
    if not result.chain or not _has_reverse_in_chain(result.chain):
        return result
    if result.flags:
        return result
    from src.policy import _is_base64_like
    if _is_base64_like(result.output) or (len(result.output) > 60 and result.score <= 200):
        result.score = max(result.score - 160, 5)
    elif result.score <= 160:
        result.score = max(result.score - 80, 5)
    return result


def _suppress_noise_family(all_results: list[DecodeResult]) -> list[DecodeResult]:
    """Suppress repetitive low-value shift families while keeping a tiny representative sample."""
    noise_groups = {}
    for r in all_results:
        if not r.chain or len(r.chain) < 2:
            continue
        if r.chain[-1].startswith("CAESAR_SHIFT_") and not r.flags:
            parent_key = tuple(r.chain[:-1])
            noise_groups.setdefault(parent_key, []).append(r)

    for _parent_key, group in noise_groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda x: x.score, reverse=True)
        keep_count = 1
        for i, r in enumerate(group):
            if i >= keep_count:
                # Push repeated same-family shift noise well below meaningful
                # intermediate results so top-N stays readable.
                r.score = -50 - i
                r.confidence = "NOISE"

    return all_results


def run_all_decoders(text: str) -> list[DecodeResult]:
    results = []
    for decoder in ALL_DECODERS:
        try:
            result = decoder(text)
            if result.status == "success" and result.output:
                _score_result(result, previous_input=text)
            results.append(result)
        except Exception as e:
            results.append(DecodeResult(
                method=_get_method_name(decoder),
                status="failed",
                error=str(e),
            ))

    for shift in range(1, 26):
        try:
            result = decode_caesar(text, shift)
            if result.status == "success" and result.output:
                _score_result(result, previous_input=text)
            results.append(result)
        except Exception as e:
            results.append(DecodeResult(
                method=f"CAESAR_SHIFT_{shift}",
                status="failed",
                error=str(e),
            ))

    results.sort(key=lambda r: r.score, reverse=True)
    return results


def run_recursive_decoders(text: str, max_depth: int = 3, max_branch: int = 5, show_applicability: bool = False, applicability_log: list = None) -> list[DecodeResult]:
    seen_outputs: set[str] = set()
    seen_chains: set[tuple[str, ...]] = set()
    all_results: list[DecodeResult] = []
    pending: list[tuple[str, list[str]]] = [(text, [])]
    depth_level = 0

    while pending and depth_level < max_depth:
        depth_level += 1
        next_pending: list[tuple[str, list[str]]] = []

        for current_text, current_chain in pending:
            if len(current_text) < 4 or len(current_text) > 5000:
                continue

            policy = get_transition_policy(current_text)
            expandable = [(name, score, reason) for name, score, reason in policy if score >= 10]
            expandable = expandable[:max_branch] if max_branch > 0 else expandable
            if show_applicability and applicability_log is not None:
                applicability_log.append({
                    "layer": depth_level,
                    "input": current_text[:80] + ("..." if len(current_text) > 80 else ""),
                    "policy": expandable,
                })

            for name, score, reason in expandable:
                if name == "CAESAR":
                    if _is_base64_like(current_text):
                        continue
                    for shift in range(1, 26):
                        method_name = f"CAESAR_SHIFT_{shift}"
                        try:
                            result = decode_caesar(current_text, shift)
                            if result.status != "success" or not result.output:
                                all_results.append(result)
                                continue
                            new_chain = current_chain + [method_name]
                            if result.output in seen_outputs or tuple(new_chain) in seen_chains:
                                all_results.append(result)
                                continue
                            seen_chains.add(tuple(new_chain))
                            result.chain = new_chain
                            _score_result(result, previous_input=current_text)
                            all_results.append(result)
                            if _should_expand(result, current_text):
                                seen_outputs.add(result.output)
                                next_pending.append((result.output, new_chain))
                        except Exception:
                            all_results.append(DecodeResult(
                                method=method_name,
                                status="failed",
                                chain=current_chain + [method_name],
                            ))
                    continue

                decoder = DECODER_BY_NAME.get(name)
                if decoder is None:
                    continue

                try:
                    result = decoder(current_text)
                    if result.status != "success" or not result.output:
                        all_results.append(result)
                        continue

                    new_chain = current_chain + [name]

                    if result.output in seen_outputs or tuple(new_chain) in seen_chains:
                        all_results.append(result)
                        continue
                    seen_chains.add(tuple(new_chain))

                    result.chain = new_chain
                    _score_result(result, previous_input=current_text)
                    all_results.append(result)

                    if _should_expand(result, current_text):
                        seen_outputs.add(result.output)
                        next_pending.append((result.output, new_chain))

                except Exception:
                    all_results.append(DecodeResult(
                        method=name,
                        status="failed",
                        chain=current_chain + [name],
                    ))

        pending = next_pending

    all_results = _suppress_noise_family(all_results)
    for r in all_results:
        _apply_reverse_penalty(r)
    all_results.sort(key=lambda r: r.score, reverse=True)
    return all_results
