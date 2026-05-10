"""Framework integrations for Cordon.

Each submodule wraps a popular agent framework so that tool calls are
checked by a :class:`cordon.Guard` before they execute. All integrations
are duck-typed against their target framework — Cordon never imports the
framework itself, so installing Cordon does not pull in OpenAI,
Anthropic, LangChain, etc.

Available integrations:

* :mod:`cordon.integrations.openai` — wraps OpenAI tool / function calls.

Coming in v0.2:

* ``cordon.integrations.anthropic``  — Anthropic tool use
* ``cordon.integrations.langchain``  — LangChain Tool / AgentExecutor
* ``cordon.integrations.llamaindex``
"""
