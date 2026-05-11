"""Framework integrations for Cordon.

Each submodule wraps a popular agent framework so that tool calls are
checked by a :class:`cordon.Guard` before they execute. All integrations
are duck-typed against their target framework — Cordon never imports the
framework itself, so installing Cordon does not pull in OpenAI,
Anthropic, LangChain, etc.

Available integrations (v0.2):

* :mod:`cordon.integrations.openai`     — OpenAI tool / function calls.
* :mod:`cordon.integrations.anthropic`  — Anthropic Messages ``tool_use`` blocks.
* :mod:`cordon.integrations.langchain`  — LangChain ``BaseTool`` / Runnable wrappers.

Coming later:

* ``cordon.integrations.llamaindex``
"""
