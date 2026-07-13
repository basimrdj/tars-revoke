#!/usr/bin/env python3
"""Start mlx_lm.server with a narrow Gemma4 E4B compatibility fallback.

The cached `mlx-community/gemma-4-e4b-it-4bit` checkpoint contains per-layer
KV weights for layers that the current MLX Gemma4 implementation treats as
shared. `mlx_lm.server` loads with strict=True and rejects those extra weights.
Direct `load_model(..., strict=False)` instantiates the full 42-layer model.

This shim leaves the normal server path untouched. It only retries non-strict
for that exact Gemma4 extra-weight failure.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Optional, Tuple, Union

from mlx_lm import utils as mlx_utils


_original_load = mlx_utils.load


def _load_with_gemma4_retry(
    path_or_hf_repo,
    tokenizer_config: Optional[Dict[str, Any]] = None,
    model_config: Optional[Dict[str, Any]] = None,
    adapter_path: Optional[str] = None,
    lazy: bool = False,
    return_config: bool = False,
    revision: Optional[str] = None,
) -> Union[Tuple[Any, Any], Tuple[Any, Any, Dict[str, Any]]]:
    try:
        return _original_load(
            path_or_hf_repo,
            tokenizer_config=tokenizer_config,
            model_config=model_config,
            adapter_path=adapter_path,
            lazy=lazy,
            return_config=return_config,
            revision=revision,
        )
    except ValueError as exc:
        msg = str(exc)
        if "parameters not in model" not in msg or "language_model.model.layers" not in msg:
            raise

        model_path = mlx_utils._download(path_or_hf_repo, revision=revision)
        config = mlx_utils.load_config(model_path)
        if config.get("model_type") != "gemma4":
            raise

        print(
            "[start_mlx_server] Gemma4 strict load rejected shared-KV extra "
            "weights; retrying with strict=False.",
            file=sys.stderr,
        )
        model, config = mlx_utils.load_model(
            model_path,
            lazy=lazy,
            strict=False,
            model_config=model_config,
        )
        if adapter_path is not None:
            model = mlx_utils.load_adapters(model, adapter_path)
            model.eval()
        tokenizer = mlx_utils.load_tokenizer(
            model_path,
            tokenizer_config,
            eos_token_ids=config.get("eos_token_id", None),
        )
        if return_config:
            return model, tokenizer, config
        return model, tokenizer


mlx_utils.load = _load_with_gemma4_retry

from mlx_lm.server import main  # noqa: E402


if __name__ == "__main__":
    main()
