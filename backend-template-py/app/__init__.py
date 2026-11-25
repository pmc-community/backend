"""
FastAPI backend template.

Environment variables are loaded from ``.env`` (current working directory)
before any module of the application reads them - the equivalent of
``import 'dotenv/config'`` / ``node --env-file=.env`` in the original project.
Variables that are already set in the environment are never overridden.
"""

from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv(usecwd=True))
