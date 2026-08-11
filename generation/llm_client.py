"""
Groq LLM client wrapper.
"""

import logging
import os
from pathlib import Path
from dotenv import load_dotenv

# Load env variables (check root workspace dir or current dir)
load_dotenv(Path(__file__).parent.parent / ".env")
load_dotenv(Path(__file__).parent.parent.parent / ".env")
load_dotenv()

from config import GROQ_API_KEY_ENV_VAR, GROQ_MODEL

logger = logging.getLogger(__name__)

_client = None


def get_client():
    """Instantiate the Groq client using GROQ_API_KEY from env."""
    global _client
    if _client is None:
        api_key = os.environ.get(GROQ_API_KEY_ENV_VAR) or os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise ValueError(
                f"Missing Environment Variable '{GROQ_API_KEY_ENV_VAR}'. "
                "Please create a .env file with GROQ_API_KEY=gsk_... or export it in your environment."
            )
        try:
            from groq import Groq

            _client = Groq(api_key=api_key)
        except Exception as e:
            logger.error(f"Failed to initialize Groq client: {e}")
            raise
    return _client


def call_llm(
    prompt: str | dict[str, str],
    system_prompt: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 1024,
) -> str:
    """Send a prompt to Groq and return the text response.

    Supports prompt as dict {"system": ..., "user": ...} or plain string.
    """
    client = get_client()

    messages = []
    if isinstance(prompt, dict):
        sys_content = prompt.get("system") or system_prompt
        if sys_content:
            messages.append({"role": "system", "content": sys_content})
        messages.append({"role": "user", "content": prompt.get("user", "")})
    else:
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": str(prompt)})

    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if response and response.choices:
            return response.choices[0].message.content or ""
        return ""
    except Exception as e:
        err_msg = str(e)
        logger.error(f"Groq API call error: {err_msg}")
        if "rate_limit" in err_msg.lower() or "429" in err_msg:
            return "Error: Groq API rate limit reached. Please wait a moment before asking another question."
        elif "authentication" in err_msg.lower() or "401" in err_msg or "invalid_api_key" in err_msg.lower():
            return "Error: Invalid Groq API Key. Please verify your GROQ_API_KEY in .env."
        return f"Error communicating with LLM service: {err_msg}"

