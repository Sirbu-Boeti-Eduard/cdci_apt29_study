# Guidance for AI agents

These instructions apply to the whole APT29/SUNBURST study.

## Keep the project structure

- For assignment content, work in the existing `tasks/taskNN-*` or `deliverables/*` folder that matches the request. For explicit requests about agent guidance or skills, work in the existing `.agents/` folder or this root `AGENTS.md`.
- Before editing, read the root `README.md` and inspect the selected folder for its instructions, template, or examples. Follow them.
- Do not add, remove, rename, move, or reorganize project directories. Do not overwrite instructions, templates, or examples unless asked.
- Put research notes, evidence, and citations with the task that used them. Do not invent a new folder or format when the right location is unclear; ask the requesting colleague.

## Keep changes focused

- Handle one requested task at a time. Keep each change and any proposed commit or pull request small and tied to one task.
- Do not bundle unrelated task folders or unrelated edits into one commit or pull request. If one task requires several files, include only those needed and explain why they belong together.
- Review the changed-file list and diff before handing work back. Do not commit, push, open a pull request, or change GitHub settings unless asked.

## Check references and evidence

- Open each source and check that its direct link works. Search-result snippets are not evidence. Use the source type that fits the claim: official reports and advisories, vendor threat research, reputable security blogs, technical documentation, or academic papers. Blogs and security write-ups are acceptable; use peer-reviewed papers where the assignment specifically requires them, especially in `task08-papers`.
- Make every reference support the claim beside it. Include the author or publisher, title, and date when available. For a long PDF or report, give the exact page and section, figure, or table. If you used only a short passage, point to that location or choose a shorter source that supports the same claim. Do not make teammates search an entire document for one fact.
- Keep references lean: use the fewest strong sources needed, and do not add links that merely mention the topic. Follow any task template or required citation style.
- Separate what a source reports from your interpretation. Do not invent references or proof. For PoC evidence, point to the specific log, screenshot, or artifact and state what it demonstrates without claiming more than it shows.
- Check that each source's author, date, context, and URL are correct. Record references in the relevant task folder, and flag attribution or evidence that remains uncertain.

## Use the project skills

- Before drafting or editing prose for teammates, read the [write-prose skill](.agents/skills/write-prose/SKILL.md). Use its advice for direct, plain wording. Keep the task's required format, evidence, and the team's instructions when applying the style guidance. Upstream: [AnswerDotAI/skill-plugins](https://github.com/AnswerDotAI/skill-plugins/tree/main/plugins/codex-aai/skills/write-prose), Apache-2.0.
- Before reviewing a non-trivial GitHub diff or preparing a pull request, read the [scope-creep-detector skill](.agents/skills/scope-creep-detector/SKILL.md) and its `references/scope-signals.md`. Run its local diff check when useful. Treat its findings as review prompts, not proof that a change is out of scope. Upstream: [Shubhamsaboo/awesome-llm-apps](https://github.com/Shubhamsaboo/awesome-llm-apps/tree/main/agent_skills/scope-creep-detector), Apache-2.0.

## Hand off clearly

When you finish, give the colleague who requested the work a short handoff with the files or sections changed, sources checked, and anything still unresolved. Say that you followed this repository guidance and mention the applicable skill when it materially shaped the work. For requested GitHub pull requests, put the same summary in the pull-request description. Do not message other teammates automatically.
