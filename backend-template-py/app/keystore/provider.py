import importlib
import os
from types import ModuleType


def keystore_provider() -> ModuleType:
    deploy_env = os.environ.get("DEPLOY_ENV")

    if deploy_env in ("local", "simprod"):
        return importlib.import_module("app.keystore.local.keystore")

    # if deploy_env == "production":
    #     return importlib.import_module("app.keystore.production.keystore")

    raise RuntimeError(f"Unsupported DEPLOY_ENV: {deploy_env}")
