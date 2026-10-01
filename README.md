# tausa-pages

Sitio estático de Tausa Labs, publicado con GitHub Pages desde `docs/` en
`master`. Es el repo P3 del plan de transición a Orca (`TEC-0181`): un
despliegue pequeño y real para probar el merge con gate doble sobre una
rama protegida.

- `docs/` — el sitio. Lo que entra a `master` se publica.
- `.claude/` y `CLAUDE.md` — salen de `plantilla-entorno` (commit
  `aecbb45`): los hooks de gobierno y los `deny` viajan con el repo, así
  que cada worktree los trae.

Ningún cambio llega a `master` sin pull request y sin la firma de Steve.
