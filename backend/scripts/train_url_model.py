"""
Compatibility training entrypoint for URL lexical LightGBM model.

Delegates to scripts.train_url_lexical_lightgbm so automation can call:
  python -m scripts.train_url_model ...
"""

from __future__ import annotations

from scripts.train_url_lexical_lightgbm import main


if __name__ == "__main__":
    main()

