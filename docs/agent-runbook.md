# Runbook de agentes — Fable 5 con delegación puntual a Opus

Objetivo: seguir trabajando con **Fable 5** como agente principal y, cuando una
acción concreta "salte", enrutarla al destino correcto — que a veces es un
**subagente Opus**, pero muchas veces NO (a veces es corregir permisos o
reescribir el comando). Este doc enseña a distinguirlo para no delegar a ciegas.

> Regla de oro: **delegar a Opus solo resuelve UNA de las cuatro causas de
> fallo** (rechazo del modelo por contenido dual-use). Para las otras tres, un
> subagente Opus hereda las mismas limitaciones y no cambia nada.

---

## 1. Taxonomía de fallos (qué "salta" y por qué)

| Tipo | Síntoma | Causa real | ¿Opus lo resuelve? | Fix correcto |
|---|---|---|---|---|
| **A. Deny explícito** | "Permission … denied" sobre `.env`, `.ssh`, `.aws` | Regla `deny` en `settings.json` (protege secretos) | ❌ No (hereda el deny) | Es intencional. No bypassear. Si de verdad se necesita, pedirlo al usuario. |
| **B. No allowlisted** | "Permission … denied" sobre un binario común (`cat`, `docker`, `psql`…) | El comando no está en `allow` | ❌ No (hereda permisos) | Usar la herramienta dedicada (Read/Grep/…) **o** allowlistar el binario en settings. |
| **C. Error de shell / generación** | `unexpected EOF`, comando cortado a media comilla, "completed with no output" | Comillas sin cerrar, one-liner largo con `%{}`/`$()`, statement incompleto | ⚠️ Marginal | Reescribir el comando (ver §4). No es un flag. |
| **D. Rechazo del modelo** | El modelo se niega/vacila ante una tarea **dual-use legítima** (pentest autorizado, exploit dev, C2…) | Medidas extra de Fable 5 sobre capacidades dual-use | ✅ **Sí** | Delegar ESA tarea puntual a un subagente Opus con contexto de autorización. |

Fable 5 lleva medidas de seguridad adicionales sobre capacidades dual-use que
Opus 4.8 no; por eso **el único caso donde delegar a Opus es el arreglo real es
el Tipo D**. Todo lo demás se resuelve en Fable.

---

## 2. Árbol de decisión (cuando algo salta)

```
¿El comando falló / se negó?
│
├─ ¿Mensaje de "permission denied"?
│   ├─ ¿Es .env/.ssh/.aws/secreto?        → Tipo A: NO bypassear. Avisar al usuario.
│   └─ ¿Binario común no allowlisted?      → Tipo B: usar tool dedicada o allowlistar.
│
├─ ¿Error de bash (EOF, quote, comando cortado)?
│                                          → Tipo C: reescribir (heredoc, 1 propósito). Reintentar en Fable.
│
└─ ¿El MODELO se negó/vaciló ante tarea dual-use AUTORIZADA?
                                           → Tipo D: delegar ESA tarea a Opus (plantilla §3).
```

---

## 3. Protocolo de delegación a Opus (solo Tipo D)

Fable sigue de main; se lanza un subagente **solo para el paso puntual que el
modelo no quiso hacer**, con contexto de autorización explícito, y Fable retoma
con el resultado.

Plantilla de invocación (herramienta `Agent`):

```
Agent(
  subagent_type: "general-purpose",
  model: "opus",
  description: "<3-5 palabras>",
  run_in_background: false,   // necesito el resultado para continuar
  prompt: """
  CONTEXTO DE AUTORIZACIÓN: <pentest/CTF/investigación defensiva; quién autoriza; alcance>.
  TAREA PUNTUAL (aislada): <exactamente el paso que saltó, con inputs y output esperado>.
  NO hagas nada fuera de esta tarea. Devuelve <artefacto/resultado> y una nota de qué hiciste.
  """
)
```

Notas:
- `model: "opus"` fuerza Opus para ese subagente aunque el main sea Fable.
- Aislar la tarea: el subagente arranca en frío, así que el prompt debe llevar
  todo el contexto (no asume lo que Fable ya sabe).
- El resultado del subagente vuelve a Fable como texto; Fable continúa el resto.
- **No** delegar Tipos A/B/C aquí: el subagente hereda permisos y settings, así
  que un deny o un `cat` no-allowlisted vuelve a fallar igual.

---

## 4. Reglas para escribir Bash robusto (mata el ~90% de los "truncados" Tipo C)

1. **Un comando = un propósito.** No encadenar 6 statements con `;` y comillas
   anidadas en una sola llamada. Si son pasos, son llamadas separadas.
2. **Multi-línea con comillas → heredoc.** Esto fue 100% fiable esta sesión:
   ```bash
   bash <<'SH'
   set -e
   TOK=$(curl -s ... | jq -r '.data.token')
   curl -s -w '%{http_code}\n' ... -H "Authorization: Bearer $TOK"
   SH
   ```
   Las comillas viven dentro del heredoc `'SH'` (sin expansión), no compiten con
   las del one-liner.
3. **`curl -w` corto y balanceado.** Un solo `-w '%{http_code}\n'` por comando;
   nunca partir un `"%{http…` a medias.
4. **Nunca `cat`/`sed`/`echo`/`head` para leer archivos** → usar `Read`/`Grep`
   (además están allowlisted; `cat` no).
5. **Variables no persisten entre llamadas Bash.** Si necesitas `$SP` en varios
   pasos, redefínela en cada llamada o mételo todo en un heredoc.
6. **Si permisos deniegan, NO reintentar igual.** Clasificar (A/B) y actuar; el
   reintento idéntico vuelve a fallar.

---

## 5. Ajustes de settings que evitan fricción (opcional, decisión del usuario)

- Los deny de `.env*`/`.ssh`/`.aws` **déjalos** — protegen secretos.
- Si quieres que los pipelines usen `cat`/`docker`/`curl` sin prompt, allowlista
  esos binarios (skill `update-config` o editar `settings.json → allow`).
  Ejemplo mínimo para este backend:
  `Bash(docker *)`, `Bash(curl *)`, `Bash(jq *)`, `Bash(mysqladmin *)`.
  (No allowlistees `cat *` global si prefieres forzar el uso de `Read`.)

---

## 6. Bitácora de esta sesión (evidencia)

| Comando | Resultado | Tipo | Qué se hizo |
|---|---|---|---|
| `cat .env.example` / `Read .env.example` | denied | A (deny `Read(./.env.*)`) | Se omitió; es secreto por diseño |
| `cat Makefile` | denied | B (`cat` no allowlisted) | Se leyó con la tool `Read` |
| `grep -rn "…\|NewU` (sin cerrar) | `unexpected EOF` | C | Reescrito y reintentado en Fable |
| `curl … -w "…%{http` (cortado) | `unexpected EOF` | C | Reescrito corto en Fable |
| Bloque `SP=…` sin cuerpo | "no output" | C (statement incompleto) | Reescrito |
| _(ningún caso)_ | — | D | No hubo rechazo de modelo: todo el trabajo fue benigno |

Conclusión de la sesión: **cero** casos Tipo D. Lo que se leyó como "flag de
Fable" fueron Tipos A/B/C. La estructura queda lista para el día que aparezca un
Tipo D real.
