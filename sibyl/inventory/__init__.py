"""The workspace inventory: workspaces, repositories, services, SBOMs, components, questions.

Writes go straight to Postgres. Agents read the same tables through Zetaris
(datasource `inventory`, and the `sibyl.inventory` USL model).
"""
