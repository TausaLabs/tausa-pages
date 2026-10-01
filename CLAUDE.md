# CLAUDE.md — base de gobierno de esta raíz

Esto es lo mínimo que cualquier raíz de trabajo con Claude Code necesita
para operar con control desde el primer día. Nace de `TEC-0169` (Tausa
Labs), que lo extrajo de un entorno en producción — no es teoría.

## Dueño de la raíz

Cada carpeta de proyecto que use esta plantilla tiene **un solo dueño
humano**, la persona que aprueba lo que aquí se llama "techo duro" (ver
abajo) y a quien Claude Code rinde cuentas. Si esta raíz sirve a varias
personas o varias compañías, cada una necesita su propia raíz, con su
propio `.claude/`: gobernar dos dueños desde una sola raíz es la forma
más común de terminar aprobando en nombre de alguien sin querer.

Anota aquí quién es el dueño de esta raíz en cuanto la instancies:

- **Dueño:** _(nombre de la persona, no de un rol ni de una compañía)_

## Techo duro

"Techo duro" es la lista corta de actos que ningún agente ejecuta sin
que el dueño de la raíz lo apruebe explícitamente, sin importar cuánta
autonomía haya ganado ese agente en todo lo demás:

- Desplegar a producción.
- Gastar dinero o crear una credencial nueva.
- Borrar algo de forma irreversible.
- Publicar un paquete o hacer push a un remoto compartido.
- Tocar la configuración de gobierno misma (este archivo,
  `.claude/settings.json`, los hooks).

El techo duro no se relaja con el tiempo ni con la confianza ganada: un
agente que lleva un año sin errores sigue sin poder desplegar solo. Los
tres hooks de `.claude/hooks/` aplican una parte de esto en código
(`guarda_techo_duro.py` bloquea el patrón de comando, no la intención;
un acto de techo duro por una vía que el hook no reconoce todavía sigue
siendo techo duro, y se corrige el hook cuando aparece).

## Dónde viven los accesos, y que nunca se leen

Las credenciales, tokens y secretos de esta raíz **no viven en este
repo, ni en ningún repo**: viven en el gestor de secretos o el
almacenamiento cifrado que el dueño de la raíz decida (variables de
entorno, un vault, el gestor de secretos de su nube). `.claude/settings.json`
declara en `permissions.deny` las carpetas donde vive ese material
(`Agente_Accesos/**`, `Accesos/**`, `gates_telegram/**` — nombres
heredados del entorno de origen; renómbralos aquí si tu convención es
otra) para que ningún agente pueda leerlas, editarlas ni escribirlas,
nunca, sin excepción por nombre de tarea.

Un agente puede **usar** un secreto (leerlo de una variable de entorno
en tiempo de ejecución) sin **verlo** (que su valor entre al contexto
del modelo). Esa distinción es la que separa "construye código que lea
`$API_KEY`" de "muéstrame el valor de `$API_KEY`": lo primero es
trabajo normal, lo segundo es techo duro aunque parezca inocente.

## Las cinco reglas

1. **Un dueño por raíz.** Ver arriba. Sin excepción por conveniencia.
2. **Firma solo para techo duro.** Todo lo demás — leer, escribir
   código, correr tests, abrir un PR — no necesita aprobación previa.
   Pedir firma para todo entrena al dueño a aprobar sin leer.
3. **Merge solo por PR con rama protegida.** Nada llega a la rama
   principal sin pasar por una revisión, ni siquiera un cambio de una
   línea del propio dueño. La rama protegida es lo que hace la regla 4
   verificable en vez de honor.
4. **Quien revisa no escribe.** El agente o la persona que aprueba un
   PR no es el mismo que lo escribió. Si solo hay un agente disponible,
   la revisión la hace el dueño humano: revisar tu propio trabajo no es
   revisión, es una segunda lectura del mismo sesgo.
5. **Árbol limpio antes de lanzar.** Ningún agente empieza una tarea
   nueva con cambios sin commitear de una tarea anterior en el árbol de
   trabajo. Un árbol sucio es la forma más fácil de mezclar la
   evidencia de dos tareas distintas sin darse cuenta.

## Qué hace el resto de la plantilla

- `.claude/settings.json` engancha los tres hooks de gobierno y el
  `permissions.deny` de accesos — ver `README.md` para el detalle de
  cada hook.
- `agentes/ejemplo.toml` es el punto de partida si esta raíz también va
  a definir agentes con una fábrica propia (ver `agentes/README.md`).
- `probar_plantilla.py` prueba que los tres hooks se comportan igual
  una vez copiada esta carpeta a la raíz nueva, antes de confiar en
  ellos para nada más.

Este archivo es la base. Cada raíz que lo instancie le agrega encima lo
que sea propio de su compañía o su cliente — el dueño, sus reglas de
negocio, su vocabulario — sin borrar ninguna de las cinco reglas de
arriba.
