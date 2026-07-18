# filething — Especificación FINAL del formato Block y Manifest (MVP)

Versión 1.0 — lista para construir. Esta es la especificación única, normativa, del formato más caro de cambiar de filething: cómo se representan los **Block**, el **Manifest**, la **Revision** y el grafo content-addressed que vive en el **Vault**, y qué punteros diminutos viven en el **Coordinator**.

Está injertada de tres diseños independientes (`mvp-minimal`, `restic-git`, `convex-first`) y corrige TODAS las fallas de correctitud alta/media que señalaron los jueces. Las decisiones load-bearing nuevas (que no estaban en la memoria del proyecto) están marcadas con **[DECISIÓN]** para que las registres en un ADR.

Convenciones: tamaños binarios (KiB = 2^10, MiB = 2^20). Toda longitud entera en el wire es little-endian salvo que se diga lo contrario. JSON canónico = claves ordenadas lexicográficamente por bytes UTF-8, sin espacios.

> **Estado de implementación (2026-07):** esta spec sigue siendo la biblia normativa y no
> cambia. Lo que sí cambió es qué está construido: donde el texto dice "MVP = `alg=0` / cifrado
> OFF" y "`alg=1` = futuro", el cifrado en runtime **`alg=1`** (XChaCha20-Poly1305, data key/nonce
> deterministas por cuenta, sidecars `keys/*`) ya está **implementado desde la Fase 3** (ADR 0015).
> Los **Blocks** de contenido se cifran (`alg=1`); los **manifests** siguen en claro (`alg=0`,
> zero-knowledge diferido). El **Vault mixto** que describe §11 es el estado real: Blocks `alg=0`
> pre-Fase 3 coexisten con `alg=1`. Lee las columnas "futuro (`alg=1`)" como "vigente", no pendiente.

---

## 1. Resumen y principios

filething sincroniza un **Space** (árbol de archivos) entre los **Devices** de una **Account** vía dos planos que nunca se mezclan:

- **Coordinator** (Convex, TypeScript): plano de control. Documentos diminutos, reactividad, el puntero de cabeza (**Space head**) y la cadena lineal de **Revisions**. NUNCA ve bytes de archivo ni la **Space key**.
- **Vault** (R2 / S3-compatible): almacén content-addressed e inmutable. Guarda **Block** y **páginas de Manifest**. El Coordinator nunca lo lee.

Cinco principios rectores, de los que se deriva todo lo demás:

1. **Convex-first.** Ningún documento de Convex puede crecer con el número de archivos o de bytes del Space. Todo lo que escala vive content-addressed en el Vault; Convex solo guarda hashes de 32 bytes y escalares de control. Esto satisface por construcción los límites duros de Convex (1 MiB/doc, 16 MiB/txn, 16 MiB args, 1s CPU/mutation).
2. **Merkle en todo.** Block, páginas de Manifest y el árbol de Manifest son objetos content-addressed e inmutables (estilo git/restic). Esto da integridad gratis (re-hashear = verificar), dedup estructural entre Revisions, diff por poda de hash y un grafo de alcanzabilidad limpio para GC.
3. **Direccionar por el ciphertext, dedup por el cleartext.** El nombre de un Block es el hash de los bytes almacenados (ciphertext cuando haya cifrado). El hash del cleartext es la llave de dedup con scope = Account, nunca cross-account, y nunca es nombre de objeto.
4. **El hueco de cifrado existe desde el día 1.** El MVP sube en claro, pero el layout reserva exactamente los campos (algoritmo, nonce, data key envuelta vía sidecar) para que activar cifrado NO cambie el layout, el naming ni el schema. Las decisiones que el cifrado vuelve irreversibles (cómo se deriva la data key, dónde vive el wrap) se fijan AHORA.
5. **Capa semántica separada del grafo opaco.** Los nombres/rutas viven DENTRO de las páginas de Manifest en el Vault; el Coordinator solo ve hashes opacos. Esto deja el camino a zero-knowledge sin cambiar el schema de Convex.

Lenguaje ubicuo (se usa en mayúscula inicial a lo largo del documento): **Space**, **Account**, **Device**, **Block**, **Manifest**, **FileEntry**, **Revision**, **Space head**, **Coordinator**, **Vault**, **Space key**, **chunk secret**, **dedup secret**, **cid** (content id = hash de direccionamiento), **pcid** (plaintext content id = hash de dedup).

---

## 2. Primitivas (valores concretos y justificación)

| Primitiva | Elección | Justificación |
|---|---|---|
| Hash de direccionamiento e integridad | **BLAKE3-256** (salida 32 bytes) | Más rápido que SHA-256 (SIMD + árbol interno, paraleliza sobre archivos grandes), sin length-extension, 256 bits = margen anti-colisión holgado para un store content-addressed. Un solo hash sirve para `cid`, `pcid`, naming de objetos, verificación de wire y —vía su modo KDF— para derivar la gear table de FastCDC, la data key y el nonce. No se añade ninguna otra primitiva de hashing. |
| KDF (derivación de subclaves) | **BLAKE3 modo `derive_key`** con context strings de dominio | Una raíz (Space key / dedup secret) → subclaves por dominio sin reusar clave entre wrap, chunking y data keys. Context strings fijados en §2.1. |
| Codificación de nombres de objeto e IDs | **hex en minúsculas** (64 chars para 32 bytes) | ASCII puro, seguro como key de R2/S3 y como string en Convex; sin `+`/`/`/`=` de base64 que rompen keys o URLs; case-insensitive-safe. Habilita fan-out por prefijo de 2 chars (estilo `.git/objects/ab/`). Cuesta más chars que base32/base64 pero las keys quedan holgadas bajo el límite de 1024 de R2. |
| Serialización de páginas de Manifest | **CBOR canónico** (RFC 8949 §4.2.1: enteros mínimos, claves ordenadas, sin indefinite-length) | Determinista byte-a-byte (requisito DURO de content-addressing: el mismo árbol lógico debe producir el mismo hash en cualquier Device), compacto, con bytestrings nativos para hashes (sin overhead base64). JSON no es determinista ni tiene bytestrings; los ejemplos JSON de esta spec son ilustrativos, el formato en el wire es CBOR canónico. |
| Cuerpo del Block | bytes crudos del payload tras un header de longitud fija | El payload ES el contenido (plaintext en MVP, ciphertext con cifrado). Header de tamaño fijo para que el offset del payload no dependa del cifrado. |
| AEAD (RESERVADO, OFF en MVP) | **XChaCha20-Poly1305** | Nonce de 192 bits ⇒ nonce determinista o aleatorio sin riesgo de reuso ni contador coordinado entre Devices. Rápido en software puro (sin AES-NI ⇒ uniforme Mac / VPS ARM/x86). AEAD autentica el payload (defensa extra contra un Vault malicioso). |
| Wrap de la data key (RESERVADO) | **XChaCha20-Poly1305** con la Space key como KEK (envelope encryption) | Rotar la Space key = re-envolver data keys de 32 bytes, sin re-cifrar ni renombrar Blocks. El wrap vive en un **sidecar** (§4.5), no en el cuerpo direccionado, para que rotar no cambie el `cid`. |
| Space key (RESERVADO) | 32 bytes aleatorios, custodiada en escrow por la Account (recuperable vía login) | Default escrow = decisión del proyecto. |
| chunk secret (por-Space) | 32 bytes aleatorios, NO derivados de la Space key | Siembra FastCDC (§3). Por-Space y secreto ⇒ los cortes son impredecibles, cerrando el canal lateral de tamaños. |
| dedup secret (por-Account) **[DECISIÓN]** | 32 bytes aleatorios, NO derivados de la Space key | Deriva la data key y el nonce DETERMINISTAS por contenido para habilitar dedup cross-Device bajo cifrado (§4.4). Custodiado en escrow por la Account igual que la Space key. |

### 2.1 Context strings de KDF (fijados)

```
"filething.cdc.gear.v1"     -> gear table de FastCDC (entrada: chunk secret)
"filething.block.key.v1"    -> data key por contenido      (entrada: dedup secret, info=pcid)
"filething.block.nonce.v1"  -> nonce por contenido          (entrada: dedup secret, info=pcid)
"filething.keywrap.v1"      -> subclave de wrap             (entrada: Space key)
"filething.manifest.key.v1" -> data key de página Manifest  (entrada: Space key, info=page pcid)  [zero-knowledge futuro]
```

---

## 3. Chunking FastCDC

- Algoritmo: **FastCDC con normalized chunking nivel 2** (DOS máscaras alrededor del avg). Content-defined real, no chunking fijo. El normalized chunking es lo que estrecha la distribución alrededor del avg y respeta min/max sin sesgo geométrico hacia max — es parte normativa, no un detalle.
- **Parámetros concretos:**

  | Param | Valor | |
  |---|---|---|
  | `min` | **16 KiB** (16384) | suelo: evita explosión de micro-Blocks y acota el conteo de objetos; con header de 64 B el overhead queda < 0.4 %. |
  | `avg` | **64 KiB** (65536, máscara objetivo) | sweet spot para sync de **código** (no backup): un archivo de fuente típico (1–50 KiB) cabe en 1 Block, y editar una línea re-chunkea solo ese archivo moviendo 1–2 Blocks. |
  | `max` | **256 KiB** (262144) | techo de varianza; cada Block sube en un solo PUT de R2 sin multipart; acota memoria de buffering en la CLI Rust. |

  Ratio 1:4:16 (min:avg:max), el clásico de FastCDC.

- **Justificación del avg bajo (vs el ~1 MiB de restic):** `mvp-minimal` y `convex-first` eligieron 64 KiB; `restic-git` eligió 1 MiB con min 256 KiB, lo que —como señaló su propio juez— **elimina el delta intra-archivo para el corpus típico de código** (todo archivo < 256 KiB es 1 Block, editar 1 byte re-sube el archivo entero). Para un sync de código eso es inaceptable. Adoptamos **16/64/256 KiB**: hay delta real dentro de archivos de fuente medianos y el conteo de objetos sigue acotado por el min de 16 KiB. Trade-off aceptado: más objetos que con avg 1 MiB (ver nota de archivos chicos).

- **chunk secret por-Space (constraint 4):** 32 bytes aleatorios generados al crear el Space, NO derivados de la Space key (rotar la Space key no debe re-chunkear el mundo). Siembra la gear table de 256 entradas `u64` vía `gear[i] = BLAKE3.derive_key("filething.cdc.gear.v1", chunk_secret)` expandido a 256·8 bytes (XOF). Vive en el blob de metadata del Space (en claro en MVP; opaco/cifrable en zero-knowledge). Consecuencia esperada y aceptada: el dedup NO cruza Spaces (el mismo archivo en dos Spaces produce cortes y `cid` distintos) — coherente con scope de dedup = Account/Space, no global.

- **Nota de archivos chicos / conteo de objetos (constraints 4, 12):** un archivo < `min` = exactamente 1 Block = 1 objeto. Un Space con cientos de miles de archivos diminutos ⇒ cientos de miles de objetos. R2 no cobra por objeto almacenado y `DeleteObject` es gratis, pero el conteo alto encarece el GC (enumerar) y un clon inicial (muchos GET). **Aceptado para el MVP.** Mitigación futura reservada: *packing* de Blocks chicos en super-objetos (§11), que NO cambia el Manifest ni el `cid` —sí cambia cómo se resuelve un GET de Block, vía una capa de indirección pack→(objeto, offset, len)— y por eso se difiere.

---

## 4. Block

Un **Block** es un chunk producido por FastCDC sobre el contenido en claro de un archivo. Vive como **un objeto por Block** en el Vault (constraint 12: borrar = `DeleteObject`, gratis en R2).

### 4.1 Dos identidades de un Block (constraint 1)

| Identidad | Hashea | Dónde vive | Para qué |
|---|---|---|---|
| `cid` | los **bytes almacenados** del payload (ciphertext con cifrado; cleartext en MVP) | nombre del objeto + FileEntry + Convex (vía manifestRoot, transitivo) | **direccionamiento**; es el ID opaco del grafo de referencias |
| `pcid` | los **bytes en claro** del chunk | SOLO índice local del Device + tabla de dedup scope-Account | **dedup** scope-Account |

`cid = BLAKE3-256(payload almacenado)`. `pcid = BLAKE3-256(cleartext del chunk)`.

En MVP (sin cifrar) `payload almacenado == cleartext`, así que `cid == pcid` por coincidencia, pero **el código los trata como campos separados desde el día 1**. Direccionar por ciphertext evita el cifrado convergente (no filtra igualdad de contenido cross-account); `pcid` es el puente que permite dedup intra-Account aun cuando, con cifrado on, dos cifrados del mismo claro deben dar el mismo `cid` (ver §4.4, la pieza que los tres diseños tenían rota).

### 4.2 Nombre del objeto en el Vault

```
blocks/<aa>/<cid_hex>
```

donde `<aa>` = primeros 2 chars de `cid_hex` = fan-out de 256 prefijos (estilo git, ayuda a enumerar/listar en GC y evita directorios planos gigantes). Ejemplo: `blocks/9f/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`.

Content-addressed e inmutable ⇒ re-subir un Block existente es un no-op idempotente seguro (mismo `cid` ⇒ mismo objeto). Antes de un PUT se puede hacer `HEAD blocks/<aa>/<cid>` para ahorrar ancho de banda.

### 4.3 Cuerpo del objeto: header fijo de 64 B + payload

Cada objeto Block es un header binario de **64 bytes fijos** seguido del payload. El header reserva los huecos de cifrado SIN que el cuerpo direccionado dependa de la rotación (la data key envuelta NO va aquí; va en sidecar, §4.5).

```
offset size  campo            MVP (alg=0)             futuro (alg=1)
------ ----  ---------------  ----------------------  ----------------------------
0      4     magic            "FTB1" (0x46544231)     "FTB1"
4      1     header_version   1                       1
5      1     alg              0 (cleartext)           1 (XChaCha20-Poly1305)
6      1     flags            0                       bitfield reservado
7      1     reserved         0                       0
8      8     payload_len      u64 LE                  u64 LE (len del ciphertext)
16     24    nonce            24 bytes 0x00           nonce determinista (§4.4)
40     24    reserved         24 bytes 0x00           reservado
64     ...   payload          chunk en CLARO          ciphertext AEAD (incluye tag)
```

**[DECISIÓN] El `cid` se computa sobre `nonce || payload`, NO sobre el objeto entero, y NUNCA incluye la data key envuelta.** Es decir:

```
cid = BLAKE3-256( nonce || payload )
```

Razones (corrige fallas altas de los tres diseños):
- Excluir la data key envuelta del `cid` permite que **rotar la Space key** re-envuelva data keys sin cambiar el `cid` ⇒ sin renombrar objetos (rotación barata, decisión del proyecto). Por eso la data key envuelta vive en sidecar (§4.5), fuera de los bytes hasheados.
- Incluir el `nonce` hace que dos Blocks con el mismo claro pero distinto cifrado tengan `cid` distinto cuando deban tenerlo; y como el nonce es DETERMINISTA por contenido (§4.4), el mismo claro en la misma Account produce el mismo `nonce` ⇒ el mismo `cid` ⇒ dedup cross-Device real.
- En MVP `nonce` son ceros ⇒ `cid = BLAKE3-256(payload) = pcid`. **Aclaración normativa (v1.0.1):** para que esta igualdad sea EXACTA, en MVP (`alg=0`) el `cid` se computa sobre el payload SIN anteponer el nonce de 24 bytes (el nonce efectivo en el hash es vacío), de modo que `cid = BLAKE3-256(payload) = pcid`. El nonce de 24 ceros vive en el header como campo reservado pero no entra al hash en MVP. Solo con cifrado (`alg=1`) el `cid` se computa sobre `nonce_24 ‖ ciphertext`. Esto resuelve la aparente contradicción "nonce de 24 ceros vs `BLAKE3(payload)`" y es lo que implementa `ft-block`.

**Verificación de integridad del wire (regla DURA):** al bajar un Block, se recomputa `BLAKE3-256(nonce || payload)` extraídos del objeto y se compara con el `cid` esperado. NUNCA se hashea el objeto entero (eso fallaría tras una rotación, que cambia el sidecar pero no el objeto). El header (`alg`, `nonce`, etc.) se autentica adicionalmente, con cifrado on, como **AAD del AEAD** del payload, de modo que no sea maleable.

### 4.4 Cómo funciona el dedup por-Account con cifrado — la tensión resuelta [DECISIÓN]

Esta es la falla de severidad ALTA que los tres diseños compartían: con data key y nonce **aleatorios** por-Block, dos Devices de la misma Account cifrando el mismo chunk producen ciphertext distinto ⇒ `cid` distinto ⇒ NO deduplican, y peor, no es resoluble por una tabla `pcid→cid` porque cada Device generaría un `cid` nuevo.

**Solución fijada: la data key y el nonce son DETERMINISTAS por contenido dentro de la Account.**

```
data_key(chunk) = BLAKE3.derive_key("filething.block.key.v1",   dedup_secret)  con info = pcid
nonce(chunk)    = BLAKE3.derive_key("filething.block.nonce.v1", dedup_secret)[..24]  con info = pcid
ciphertext      = XChaCha20-Poly1305.encrypt(key=data_key, nonce=nonce, aad=header, plaintext=chunk)
cid             = BLAKE3-256(nonce || ciphertext)
```

Propiedades:
- Mismo claro + misma Account ⇒ mismo `pcid` ⇒ mismos `data_key`/`nonce` ⇒ mismo ciphertext ⇒ **mismo `cid`** ⇒ dedup cross-Device real y subida idempotente (re-scan tras perder el índice produce el MISMO objeto, no un huérfano).
- Distinta Account ⇒ `dedup_secret` distinto ⇒ `data_key`/`nonce` distintos ⇒ ciphertext y `cid` distintos para el mismo claro ⇒ **no deduplica ni filtra cross-account** (no es cifrado convergente: la igualdad de contenido es invisible fuera de la Account).
- La `data_key` derivada se **envuelve igualmente con la Space key** y se guarda en el sidecar (§4.5). El wrap NO es la fuente de la data key (la fuente es la derivación determinista); el wrap existe para que **rotar la Space key** sea barato (re-envolver, sin re-derivar ni re-cifrar) y para separar el secreto de rotación (Space key) del secreto de dedup (dedup secret).

> **Contradicción con la memoria del proyecto, escalada explícitamente:** la memoria dice "data key por-Block ALEATORIA". Eso es **incompatible** con dedup-por-ciphertext cross-Device bajo cifrado: no se puede tener a la vez data key totalmente aleatoria Y que dos Devices produzcan el mismo objeto para el mismo claro. Esta spec fija **data key DETERMINISTA por contenido (derivada del dedup secret + pcid)**. La aleatoriedad real se conserva donde importa para seguridad: el dedup secret es aleatorio de 256 bits por-Account, así que la data key sigue siendo impredecible para cualquiera sin ese secreto. Registrar esta inversión en un ADR.

En MVP (cifrado OFF) el dedup es trivial: `cid == pcid`, se consulta la tabla de dedup por `pcid` y se reusa el objeto existente. Como la regla determinista ya está fijada, **activar cifrado no rompe el dedup ni obliga a re-subir** los Blocks claros existentes (coexisten `alg=0` y `alg=1`; ver §11 sobre el Vault mixto).

### 4.5 Sidecar de data key envuelta (hueco de cifrado, OFF en MVP) [DECISIÓN]

```
keys/<space_id>/<aa>/<cid_hex>   // objeto diminuto, MUTABLE bajo rotación, separado del Block inmutable
```

Contenido (CBOR canónico): `{ wrap_alg, wrap_nonce(24B), wrapped_data_key(48B = 32B ct + 16B tag) }`.

- **La clave del objeto está scoped por Space** (`<space_id>`). El objeto `blocks/<cid>` es account-scoped y se deduplica entre Spaces (mismo `dedup_secret` + `pcid` ⇒ mismo `cid`), pero el sidecar se envuelve con la **Space key** de UN Space concreto. Dos Spaces de una misma Account que comparten un chunk necesitan por tanto **un sidecar cada uno**; el componente `<space_id>` evita que colisionen en una sola clave (lo que dejaría al segundo Space sin poder desenvolver el sidecar del primero). Ver el changelog al final de §4.5.
- **No existe en el MVP** (cifrado OFF): no se escribe ningún objeto `keys/*`. El header del Block tiene `alg=0` y nadie consulta sidecars.
- Al activar cifrado: por cada Block cifrado se escribe su sidecar bajo el subárbol de su Space. Rotar la Space key = reescribir solo los sidecars de ese Space (objetos de ~88 B), sin tocar los objetos `blocks/*` ni sus `cid`.
- Esto resuelve la contradicción inline-vs-sidecar que `mvp-minimal` (slot de 32 B insuficiente) y `convex-first` (auto-contradicción) tenían: el wrap NUNCA cupo ni debió ir en el header. El header de 64 B reserva `alg`/`nonce`/`flags` (lo que SÍ es función del contenido y entra en el `cid` vía nonce); el wrap (lo que cambia con la rotación) vive aparte. Trade-off notado: con cifrado on hay ~2× objetos (Block + sidecar), aceptable y aislado al futuro.

> **Changelog (pre-deployment):** la clave del sidecar pasó de `keys/<aa>/<cid>` (sin componente de Space) a `keys/<space_id>/<aa>/<cid>`. El layout anterior colisionaba entre dos Spaces de una misma Account que compartían un chunk: el `blocks/<cid>` se deduplica pero cada sidecar se envuelve con la Space key de su Space, así que la única entrada `keys/<cid>` quedaba envuelta con la key del PRIMER Space y el segundo Space fallaba al desenvolver (Error::Decrypt) al clonar/materializar. `alg=1` aún no está desplegado en ningún entorno real, así que **no hace falta migración de datos**.

---

## 5. Manifest

Un **Manifest** es el índice del árbol completo del Space en un instante: mapea cada path canónico → lista ordenada de Blocks. NO es un documento de Convex: es un **B-tree de páginas content-addressed en el Vault**. Convex solo guarda el hash de la raíz.

### 5.1 FileEntry — la unidad

CBOR canónico (ejemplo en JSON ilustrativo):

```jsonc
{
  "p":   "src/main.rs",   // path canónico (§5.2) — KEY del Manifest
  "t":   0,               // tipo: 0=file, 1=symlink, 2=derived, 3=dir
  "x":   false,           // bit ejecutable (solo t=0)
  "sz":  12873,           // size en bytes del contenido en claro (solo t=0)
  "pcid":"<32B>",         // hash del claro del archivo COMPLETO (diff + conflicto + eco)
  "bk":  ["<cid>","<cid>"], // lista ORDENADA de cid; concatenar payloads = el archivo (solo t=0)
  "lt":  null,            // link target literal (solo t=1)
  "wu":  false            // RESERVADO: "windows-unsafe" flag opcional (default ausente/false)
}
```

Variantes por `t`:
- **`0` file:** usa `x`, `sz`, `pcid`, `bk`. El archivo = concat de los payloads (descifrados) de `bk` en orden. El orden ES el contenido; no se ordena por hash. Finales de línea **intactos** (el chunking opera sobre bytes crudos; nada normaliza CRLF/LF).
- **`1` symlink:** `lt` = target literal. Solo se preservan symlinks **relativos que no salen del Space**; absolutos o que escapan ⇒ NO entran al Manifest (el Device los materializa o los deja local-only, marcado en el índice local). `bk`/`sz`/`pcid` ausentes.
- **`2` derived:** **[DECISIÓN]** marca un path regenerable (`node_modules/`, `target/`, `.next/`, `venv/`). `bk` SIEMPRE vacío/ausente — derived no viaja byte-a-byte. El Manifest solo registra que el path existe y es derived, para que el otro Device no lo trate como borrado ni espere contenido; la regeneración la dispara la fuente sincronizada (p.ej. `package-lock.json` es una FileEntry `t=0` normal). Así el GC nunca razona sobre Blocks de derived. En el MVP (Space de juguete de archivos normales) `t=2` es estructuralmente soportado pero no ejercitado.
- **`3` dir:** **[DECISIÓN, ADR 0019]** un directorio plano trackeado como entrada de primera clase para que los **directorios vacíos** sincronicen. Solo `p` y `t` son significativos: `sz=0`, `pcid` en cero, `x=false`, `bk` vacío/ausente, sin `bk_ref` ni `lt`; NO se trackean modo/permisos. Se trackean TODOS los directorios (no solo los vacíos), así el conjunto de entradas es estable: un directorio está en el Manifest exactamente cuando existe en disco. El root del Space nunca es una entrada. Al materializar se crea el directorio (idempotente); el borrado es por AUSENCIA y se aplica con `remove_dir` (nunca recursivo) del más profundo al menos profundo — un directorio con contenido local aún no sincronizado se MANTIENE (nunca se fuerza el borrado). El chequeo derived gana antes que el de dir, así un `node_modules/` sigue siendo `t=2`.

### 5.2 Path canónico (constraint 5)

- **Forward slash** `/` siempre; **relativo** al root del Space (sin `/` inicial, sin `./` ni `../` resultantes); **UTF-8**.
- **Normalización Unicode NFC** se aplica SOLO a la KEY `p` (para ordenar, comparar y detectar colisiones). **[DECISIÓN] NFC NO se aplica al contenido** (bytes de archivo) ni al `lt` de un symlink (su target se preserva byte-exacto). Corrige la falla de `convex-first`/`restic-git` que arriesgaba corromper symlinks/contenido byte-exacto.
- **Colisión de solo-mayúsculas (constraint 5):** dos paths cuya clave `casefold(NFC(p))` coincide pero cuyo `p` difiere = **conflicto**, nunca sobre-escribir.
- **[DECISIÓN] Colisión por NFC:** dos paths byte-distintos en disco pero NFC-equivalentes (común macOS-vs-Linux con precompuesto/descompuesto) que colapsan a la misma key NFC = **conflicto**, tratado idéntico a la colisión de mayúsculas. Corrige una falla de pérdida silenciosa que `restic-git`/`convex-first` no cubrían. Implementación: al construir una página hoja, si dos FileEntries normalizan a la misma key, se emite copia de conflicto en vez de sobre-escribir.
- **Nombres ilegales/reservados de Windows:** el formato los PERMITE (Mac+Linux son byte-exactos); el flag opcional `wu` y la validación al entrar un Device Windows están reservados (§11), no aplicados en MVP.

### 5.3 Estructura paginada en B-tree (constraint 6)

El Manifest es un B-tree de páginas content-addressed en el Vault, ordenado por la key `casefold(NFC(p))`.

```
manifest/<aa>/<page_cid>
```

Dos tipos de página, ambas con header de 64 B (§4.3; `magic="FTM1"`) para reservar los mismos huecos de cifrado:

**Hoja (leaf):**
```jsonc
{ "k": 0, "v": 1, "first": "<key>", "last": "<key>", "e": [ <FileEntry>, ... ] }  // e ordenada por key
```

**Interna (index):**
```jsonc
{ "k": 1, "v": 1, "children": [ { "min": "<key>", "cid": "<page_cid>" }, ... ] }
```

La **raíz** del árbol es un único `page_cid` = `manifestRoot`. Es el único hash que entra a Convex (§6).

#### Paginación determinista (corrige falla ALTA de `restic-git`) [DECISIÓN]

El content-addressing exige que DOS Devices produzcan EXACTAMENTE el mismo árbol (mismo `manifestRoot`) para el mismo conjunto lógico de archivos, o el CAS fallaría con conflictos fantasma. Por eso el split NO es por umbral de bytes difuso. Reglas normativas:

1. **Orden total:** las FileEntries se ordenan por `casefold(NFC(p))` ascendente; empates imposibles (la colisión es conflicto, §5.2).
2. **Split de hoja por límite de entries (determinista, no por bytes):** una hoja contiene como máximo **`LEAF_FANOUT = 256` FileEntries**. Las entries ordenadas se parten en bloques contiguos de hasta 256. Esto es determinista e independiente de los tamaños de entry. Cota de tamaño: una FileEntry promedio ~120 B ⇒ hoja ~30 KiB; muy por debajo de cualquier límite.
3. **Caso patológico de una FileEntry enorme (corrige falla baja de `mvp-minimal`):** si una sola FileEntry supera **`ENTRY_INLINE_MAX = 256 KiB`** de CBOR (un archivo con decenas de miles de chunks), su lista `bk` se externaliza a un objeto `blocklist/<cid>` content-addressed y la FileEntry guarda `"bk_ref": "<cid>"` en vez de `bk` inline. Así ninguna página supera un tamaño acotado y la unidad de paginación sigue siendo la FileEntry completa. (A `max`=256 KiB por Block, un archivo de 1 GiB ≈ 4096 chunks ≈ 256 KiB de lista hex ⇒ rara vez se cruza; la regla existe para acotarlo formalmente.)
4. **Split de página interna:** una index contiene como máximo **`INDEX_FANOUT = 256` hijos**; al desbordar se crea otro nivel. Con fanout 256, dos niveles cubren 256·256·256 = ~16.7 M archivos; en la práctica el MVP tiene 1–2 niveles.
5. **Construcción bottom-up determinista:** se ordenan todas las entries, se empaquetan en hojas de 256, luego en index de 256 hijos, recursivamente, hasta una sola raíz. No hay rebalanceo incremental ni heurística: dado el conjunto de FileEntries, el árbol es función pura ⇒ `manifestRoot` reproducible en cualquier Device.

Esto fija el algoritmo completo (fanout, orden, umbral de externalización) que `restic-git` dejó subespecificado.

#### Por qué respeta los límites de Convex (constraint 6)
- Convex nunca almacena el Manifest; guarda `manifestRoot` (32 B) en el doc Revision. Doc de Convex = decenas de bytes ⇒ lejísimos de 1 MiB.
- Commit = escribir 1 doc Revision diminuto + 1 update al head ⇒ lejísimos de 16 MiB/txn y 1s CPU.
- 100k archivos: ~100k FileEntries ⇒ ~12 MiB de Manifest total en ~400 hojas + ~2 index, **todo en el Vault**. Convex no se entera del tamaño. A 10M archivos sigue igual.

### 5.4 Reuso estructural entre Revisions (delta del Manifest)

Como las páginas son content-addressed e inmutables, una Revision que cambia 5 archivos reescribe solo las hojas tocadas y la cadena de index hasta la raíz (O(log n) páginas); el resto se comparte por `page_cid` entre Revisions. Esto hace baratos a la vez el commit, el diff (§8) y el GC (§6.3).

### 5.5 Separación capa-semántica vs grafo-de-referencias-opaco (hueco zero-knowledge, constraint 10)

- **Capa semántica** (paths, nombres, `x`, `lt`, tipo): vive DENTRO de los objetos `manifest/*` del Vault. El Coordinator NO la tiene; solo ve `manifestRoot` + `cid`s (transitivos).
- **Grafo de referencias opaco** (lo único que el Coordinator necesita para feed y GC): el conjunto de `cid`/`page_cid` + `manifestRoot` + la cadena `revisions`. Ya es opaco hoy (puros hashes de ciphertext-o-cleartext, sin semántica).
- En MVP las páginas `manifest/*` van en claro (escrow: a filething no le importa ver nombres). Para zero-knowledge se cifran sus payloads con la misma maquinaria del Block (`alg=1`, data key derivada con context `"filething.manifest.key.v1"`, wrap en sidecar). El Coordinator ve EXACTAMENTE lo mismo (hashes). El chunk secret pasa de campo claro a blob opaco — el formato ya lo trata como blob. **Sin cambio de schema de Convex ni de naming del Vault.**
- Fuga residual notada (honestidad, no resoluble por el formato): aun cifrando nombres, la estructura del árbol (fan-out, conteo de Blocks por archivo, tamaños de objeto) sigue visible. El chunk secret por-Space mitiga el fingerprinting de tamaños; el resto se acepta como límite del modelo.

---

## 6. Convex (Coordinator) vs Vault

### 6.1 Vault (R2) — todo lo grande, content-addressed, inmutable

```
blocks/<aa>/<cid>        // Block: header 64B + payload (§4)
manifest/<aa>/<page_cid> // páginas hoja e index del B-tree de Manifest (§5.3)
blocklist/<aa>/<cid>     // listas bk externalizadas de FileEntries enormes (§5.3, raro)
keys/<space_id>/<aa>/<cid> // sidecar de data key envuelta, scoped por Space — NO existe en MVP (cifrado OFF, §4.5)
reach/<manifestRoot>     // sidecar de alcanzabilidad para GC en zero-knowledge — NO en MVP (§6.3)
```

Todo inmutable salvo `keys/*` (mutable bajo rotación) y `reach/*` (publicado por Device). El Coordinator nunca lee el Vault.

### 6.2 Convex — documentos diminutos (schemas TS) (constraint 6)

```ts
// spaces — una fila por Space
spaces: defineTable({
  accountId: v.id("accounts"),
  name: v.bytes(),            // metadata semántica. v.bytes() (no v.string()) para que en
                              //   zero-knowledge sea ciphertext sin cambiar el tipo. MVP: UTF-8 en claro.
  headRevisionId: v.union(v.id("revisions"), v.null()),  // EL Space head; CAS aquí
  metaBlobCid: v.bytes(),     // -> Vault: chunk secret (+ futuro material cifrable). Opaco al Coordinator.
  retentionFloorSeq: v.number(), // min(seq) que el GC NO puede barrer (§6.3). MVP: 0.
}).index("by_account", ["accountId"]),

// revisions — cadena LINEAL, UN padre (constraint 7)
revisions: defineTable({
  spaceId: v.id("spaces"),
  parent: v.union(v.id("revisions"), v.null()),  // UN padre; null = primera Revision
  seq: v.number(),                               // u64 monótono por Space (orden lineal del feed)
  manifestRootCid: v.bytes(),                    // 32B -> raíz del B-tree de Manifest en el Vault
  authorDeviceId: v.id("devices"),
  createdAt: v.number(),                         // metadata; NUNCA usado para detección de conflictos
}).index("by_space_seq", ["spaceId", "seq"])
  .index("by_parent", ["parent"]),

// devices — para el retention floor y telemetría de sync
devices: defineTable({
  accountId: v.id("accounts"),
  name: v.string(),
  baseSeqInUse: v.number(),  // min(base_seq) que este Device aún usa como base (§6.3)
}).index("by_account", ["accountId"]),

// dedup — CACHÉ opcional de aceleración cross-Device, scope ACCOUNT estricto (constraint 1)
dedup: defineTable({
  accountId: v.id("accounts"),
  pcid: v.bytes(),   // hash del CLARO. En escrow, el Coordinator lo ve; en ZK se omite o se cifra.
  cid: v.bytes(),    // -> blocks/<cid>
}).index("by_account_pcid", ["accountId", "pcid"]),
```

Notas:
- **`headRevisionId` ES el Space head**: puntero diminuto, CAS atómico (§7).
- **El change feed** = reactividad de Convex sobre `by_space_seq` y sobre `headRevisionId`.
- **`dedup` es CACHÉ, no fuente de verdad (corrige falla media de `convex-first`):** crece con el nº de Blocks distintos de la Account, lo que contradice el principio Convex-first si fuera obligatoria. El dedup REAL vive en el índice LOCAL del Device (§9) + un `HEAD blocks/<cid>` al Vault antes de subir; la tabla Convex solo acelera el caso cross-Device y puede tener TTL o estar incompleta sin afectar correctitud. Como la data key/nonce son deterministas (§4.4), un Device puede recalcular `cid` desde `pcid` y verificar existencia con un HEAD sin necesitar la tabla.
- El Coordinator nunca ve bytes de archivo ni la Space key: solo hashes, nombres (en claro en escrow, dentro de `spaces.name` y —el grueso— dentro de páginas de Manifest en el Vault), y punteros.

### 6.3 Hueco de GC reservado (constraint 9)

- **Alcanzabilidad:** un objeto del Vault está **vivo** si es alcanzable desde el Manifest de alguna Revision retenida. Enumerar = por cada Revision viva, recorrer su B-tree (`manifestRoot → index → hojas → bk` de cada FileEntry + `page_cid`s + `bk_ref`s) y unir todos los `cid`/`page_cid`. El reuso estructural (§5.4) y el content-addressing hacen el conjunto vivo compacto y el marking O(Revisions retenidas · log n).
- **En zero-knowledge:** como el Coordinator no puede leer páginas cifradas, el Device publica `reach/<manifestRoot>` = lista plana de todos los `cid`/`page_cid` alcanzables (puros hashes, sin nombres). El Coordinator marca leyendo el sidecar sin descifrar nada. Modelo de confianza notado (§11): en ZK un Device malicioso podría publicar un `reach` incompleto; mitigación (firma/verificación del sidecar) reservada.
- **[DECISIÓN] Safety GC vs commit en vuelo (corrige falla ALTA común a los tres diseños):** el orden "Vault primero, head después" (§7) deja objetos subidos pero aún no alcanzables. Un mark-and-sweep en esa ventana los borraría, corrompiendo el commit. El formato RESERVA, desde el día 1, dos protecciones (aunque el GC sea post-MVP):
  1. **Grace-period por antigüedad:** el sweep NUNCA borra un objeto cuyo `LastModified` < `GC_GRACE` (p.ej. 24 h). Ningún commit razonable tarda 24 h entre subir Vault y avanzar head.
  2. **Retention floor:** `spaces.retentionFloorSeq = min(devices.baseSeqInUse)` sobre los Devices vivos. El GC NUNCA barre objetos alcanzables desde Revisions con `seq >= retentionFloorSeq`. Esto garantiza que un Device offline que usa una Revision base vieja todavía pueda diffear y detectar conflictos (corrige la falla media de `convex-first`: diff/conflicto dependen de poder leer el Manifest de la base; si el GC la borró, degradarían a full re-scan). Si un Device estuvo offline más allá del floor, degrada explícitamente a full re-scan (comportamiento correcto, caro).
- Política de retención (cuántas Revisions guardar) y el barredor físico: fuera del MVP. La pieza cara (enumerar alcanzables + las dos protecciones) está reservada en el formato/schema.

---

## 7. Protocolo de commit (orden estricto + CAS sobre el head)

Un Device con base `B` (la Revision con la que sincronizó por última vez) y cambios locales:

```
1. CHUNK + HASH: re-chunkea archivos cambiados con FastCDC (chunk secret del Space).
   Por cada chunk calcula pcid; en MVP cid=pcid; con cifrado, deriva data_key/nonce (§4.4),
   cifra, calcula cid = BLAKE3(nonce || ciphertext).

2. DEDUP: por cada Block nuevo consulta índice local + (caché) dedup[accountId,pcid];
   si falta, HEAD blocks/<aa>/<cid>; sube SOLO los ausentes -> PUT blocks/<aa>/<cid>.
   Con cifrado, escribe también el sidecar keys/<space_id>/<aa>/<cid>. Verifica que cada PUT cerró OK.

3. CONSTRUYE el nuevo Manifest: parte de las páginas de B (content-addressed, reusadas),
   reescribe solo las hojas tocadas + ancestros hasta la raíz (§5.4), externaliza bk enormes
   a blocklist/<cid> si hace falta (§5.3). Obtiene manifestRootCid'.

4. SUBE al Vault TODAS las páginas nuevas -> PUT manifest/<aa>/<page_cid>  (y blocklist/* si aplica).

   --- INVARIANTE DE ORDEN (constraint 7): aquí TODOS los Blocks nuevos y TODAS las páginas de
       Manifest nuevas YA ESTÁN en el Vault y verificadas. NADA en Convex todavía. ---

5. COMMIT en Convex = mutation con CAS atómico. La mutation LEE el head DENTRO de la transacción
   (no confía en una lectura previa del cliente):
       const space = await db.get(spaceId);
       if (space.headRevisionId !== expectedBaseRevisionId) throw new ConflictError();  // base != head
       const rev = await db.insert("revisions",
                     { spaceId, parent: expectedBaseRevisionId, seq: space_seq_of(B)+1,
                       manifestRootCid: manifestRootCid', authorDeviceId, createdAt: Date.now() });
       await db.patch(spaceId, { headRevisionId: rev });
   Las mutations de Convex son transacciones serializables (OCC con retry): el read-then-write del
   head es atómico, y si Convex re-ejecuta por conflicto OCC, vuelve a leer el head fresco.

6. Si el CAS lanza ConflictError (otro Device avanzó el head): NO se reintenta ciego.
   El Device hace pull del head actual, RECONCILIA por archivo contra la base común (§10),
   reconstruye el Manifest y reintenta desde el paso que aplique.
```

**Garantía de crash-safety:** como Blocks y páginas se escriben ANTES de avanzar el head, toda Revision visible en Convex tiene TODO su contenido presente y verificable en el Vault. Un crash entre 4 y 5 solo deja objetos huérfanos inocuos (los recoge el GC respetando el grace-period). Nunca hay un head colgante apuntando a data inexistente. Reintentar PUTs es idempotente (content-addressed).

---

## 8. Change feed y diff entre Revisions

1. **Suscripción:** cada Device tiene una query reactiva de Convex sobre `spaces.headRevisionId` (y la Revision head: `seq`, `manifestRootCid`, `parent`). El Device conoce su `last_synced_seq`/`last_synced_root` (índice local, §9).
2. Convex empuja cuando el head cambia ⇒ el Device ve el `manifestRootCid` nuevo (32 B en el wire, nada más).
3. **Diff por poda de hash:** el Device NO baja el Manifest entero. Diffea los dos árboles content-addressed (`root_local` vs `root_head`):
   ```
   diff(a, b):
     si a == b: idénticos, poda (comparación de 32 bytes).
     baja ambas páginas; para cada par de hijos por rango de key:
       mismo page_cid    -> subárbol idéntico, PODA (no baja).
       page_cid distinto -> recursa.
     en hojas que difieren: merge-join lineal por key -> entries añadidas/modificadas/borradas.
   ```
   Un commit que tocó 5 archivos obliga a bajar O(log n) páginas; el ~99 % del árbol se poda por igualdad de `page_cid`.
4. **Aplicar:** por cada archivo cambiado, `bk_faltantes = bk_nuevos − blocks_locales`; baja SOLO esos `blocks/<cid>`, recomputa `BLAKE3(nonce||payload)` y verifica contra `cid` (integridad del wire, §4.3), descifra si `alg=1`, concatena, escribe al FS vía el adaptador OS.
5. **Merge por archivo** contra la base común: ver §10.
6. Actualiza el índice local: `last_synced_seq = head.seq`, `last_synced_root = head.manifestRootCid`.

**Delete:** un path borrado simplemente NO aparece en la nueva Revision (no hay tombstone explícito en el Manifest). El diff lo infiere como borrado. Consecuencia notada: rename = delete+add (sin tracking de identidad de archivo); move-detection futura requeriría un id estable por FileEntry, fuera del MVP.

---

## 9. Índice local por Device (constraint 11)

SQLite local en cada Device (ni en Convex ni en el Vault). Sirve para re-scan al arrancar/reconectar (SÍ es MVP), supresión de eco, dedup y detección de conflictos.

```sql
-- estado por Space en este Device
CREATE TABLE space_state (
  space_id        TEXT PRIMARY KEY,
  last_synced_seq INTEGER NOT NULL,  -- Revision base del último sync (constraint 7/11/13)
  last_synced_root TEXT NOT NULL,    -- manifestRootCid de esa base (para diff)
  chunk_secret    BLOB NOT NULL,     -- copia local del secreto FastCDC del Space
  dedup_secret    BLOB,              -- copia local del dedup secret de la Account (NULL en MVP claro)
  local_root_path TEXT NOT NULL      -- carpeta local mapeada a este Space
);

-- una fila por path sincronizado (constraint 11)
CREATE TABLE local_entry (
  space_id     TEXT NOT NULL,
  path         TEXT NOT NULL,        -- canónico (forward slash, NFC)
  casefold_key TEXT NOT NULL,        -- casefold(NFC(path)) -> colisión mayúsculas/NFC
  type         INTEGER NOT NULL,     -- 0 file / 1 symlink / 2 derived
  exec         INTEGER NOT NULL,     -- bit ejecutable
  size         INTEGER NOT NULL,     -- tamaño en claro
  mtime        INTEGER NOT NULL,     -- mtime REAL del FS tras aplicar (re-scan; NUNCA para conflictos)
  pcid         BLOB,                 -- hash del claro del archivo completo (dedup + eco + conflicto)
  base_seq     INTEGER NOT NULL,     -- Revision base POR PATH (base común para conflictos)
  blocks       BLOB,                 -- lista ordenada de {pcid, cid} por chunk (CBOR)
  local_only   INTEGER NOT NULL DEFAULT 0,  -- 1 = symlink materializado / derived no-sincronizado
  PRIMARY KEY (space_id, path)
);
CREATE INDEX idx_casefold ON local_entry(space_id, casefold_key); -- colisión barata
CREATE INDEX idx_pcid     ON local_entry(space_id, pcid);          -- dedup local

-- caché de Blocks presentes localmente ("qué me falta bajar")
CREATE TABLE local_block (
  space_id TEXT NOT NULL,
  cid      BLOB NOT NULL,
  PRIMARY KEY (space_id, cid)
);

-- dedup scope-ACCOUNT (constraint 1) — pcid -> cid ya conocido en esta cuenta
CREATE TABLE dedup_local (
  account_id TEXT NOT NULL,
  pcid       BLOB NOT NULL,
  cid        BLOB NOT NULL,
  PRIMARY KEY (account_id, pcid)   -- scope = Account, NUNCA cross-account
);
```

Usos:
- **Re-scan (MVP):** al arrancar/reconectar, recorre el FS; compara `(size, mtime)` para saltar el re-hash; si difieren, re-chunkea y compara `pcid`. Archivo en `local_entry` pero ausente en disco ⇒ borrado, se propaga (seguro: hay base/historial).
- **Supresión de eco:** tras escribir un archivo bajado del feed, registra el `mtime` **REAL** que el FS le asignó (algunos FS truncan resolución) + `pcid`; el watcher que vea ese estado lo reconoce como propio y no re-emite. Ventana de carrera notada: si el usuario edita a un contenido que casualmente iguala el aplicado (mismo `pcid`), se suprime; raro, aceptable para MVP.
- **Dedup scope-Account:** antes de subir, consulta `dedup_local` por `pcid`; con cifrado, recalcula `cid` determinista (§4.4) y/o consulta la caché Convex; HEAD al Vault como último recurso. Nunca cross-account.
- **Conflictos:** `base_seq` por path da la base común para el merge a 3 vías (§10).

---

## 10. Conflictos: diff por archivo contra la base común

Detección **causal, nunca por reloj** (decisión del proyecto; `mtime` solo acelera el re-scan). Dos niveles:

**Nivel 1 — divergencia a nivel de Space:** el CAS del §7 falla si `base != head`. NO es conflicto todavía: el Device hace pull, diffea y reconcilia.

**Nivel 2 — conflicto real por archivo:** para cada path se comparan TRES estados — `base` (Revision base común, vía `base_seq` del índice local), `local` (estado en disco) y `remoto` (la nueva Revision). La identidad "cambió" se decide por **`pcid`** (hash del claro del archivo), no por mtime:

- **Cambió en UN solo lado respecto a base** ⇒ **fast-forward** (se toma ese lado).
- **Cambió en AMBOS respecto a base** (los `pcid` de local y remoto difieren entre sí y de base) ⇒ **copia de conflicto**: se conservan ambos; el perdedor se renombra `nombre (conflicto <deviceId> <seq>).ext`.
- **Delete-vs-edit** ⇒ **gana la edición** (se restaura el archivo editado; el delete no se aplica).
- **Colisión de solo-mayúsculas o de NFC** (§5.2) ⇒ **conflicto**, nunca sobre-escribir.

Para leer el `pcid` del estado base, el Device usa la FileEntry del path en el Manifest de la base (que lo trae). Esto depende de que la base esté retenida (§6.3 retention floor); si fue barrida, el merge degrada a full re-scan. La base común en una cadena lineal de un Device es simplemente la `base_seq` registrada por path; no hay que buscar ancestro común complejo.

---

## 11. Reservas explícitas y qué NO se construye en el MVP

- **Cifrado en runtime (huecos cableados, OFF en MVP):** header de 64 B con `alg`/`nonce`/`flags`; `cid = BLAKE3(nonce||payload)` excluye la data key envuelta; sidecar `keys/<space_id>/<cid>` scoped por Space (no escrito en MVP); data key y nonce DETERMINISTAS por `pcid` (§4.4); wrap con la Space key para rotación barata. Activar cifrado: poner `alg=1`, derivar+cifrar, escribir sidecars. **No cambia layout de Block, naming del Vault, schema de Convex ni paginación de Manifest.** **Vault mixto permitido:** Blocks `alg=0` (claros, del MVP) y `alg=1` (cifrados) coexisten indefinidamente; se cifra solo lo nuevo, sin re-subir lo viejo (corrige la "migración implícita" que `restic-git` no documentaba).
- **Zero-knowledge (futuro):** cifrar payloads de páginas `manifest/*` con la maquinaria del Block; publicar `reach/<manifestRoot>` para GC; `spaces.name` ya es `v.bytes()` para volverse ciphertext sin cambio de tipo; chunk secret ya tratado como blob opaco. Fuga residual de estructura/tamaños notada; modelo de confianza del sidecar `reach` reservado.
- **GC / retención:** alcanzabilidad enumerable hoy; grace-period y retention floor reservados en el schema (§6.3). Política de retención y barredor físico: fuera del MVP.
- **Packing de Blocks chicos:** reservado vía un `magic` distinto (p.ej. `FTP1`) y una capa de indirección `cid → (pack, offset, len)`; no cambia Manifest ni `cid` semánticamente, sí cómo se resuelve un GET. Fuera del MVP.
- **Windows:** flag `wu` en FileEntry y validación de nombres reservados (`CON, PRN, AUX, NUL, COM1-9, LPT1-9`, trailing dot/space, `<>:"|?*`) reservados; se validan al entrar un Device Windows, no en MVP (Mac + VPS Linux).
- **Move-detection / tombstones explícitos:** no hay; delete = ausencia, rename = delete+add. Reservable con un id estable por FileEntry, fuera del MVP.
- **MVP construye:** motor de Block + feed bidireccional end-to-end, Mac + VPS Linux, Space de juguete de archivos NORMALES, en CLARO (`alg=0`), vault R2 gestionado, sin GC, sin escala, sin binarios per-SO.

---

## 12. Checklist final (14 puntos)

| # | Restricción | Cubierto en | Estado |
|---|---|---|---|
| 1 | Block por hash del CIFRADO; hash del CLARO = dedup scope-Account | §4.1, §4.4, §9 (`dedup_local`) | ✓ (dedup cross-Device resuelto vía data key/nonce deterministas) |
| 2 | data key aleatoria→derivada, envuelta; alg+nonce reservados sin cambiar layout | §4.3 (header 64B), §4.4, §4.5 (sidecar) | ✓ (wrap en sidecar, dimensionado correcto) |
| 3 | Funciona sin cifrar; activar cifrado no cambia layout | §4.3 (`alg=0`), §11 (Vault mixto, sin migración) | ✓ |
| 4 | FastCDC + chunk secret por-Space; params + nota archivos chicos | §3 (16/64/256 KiB, NC nivel 2) | ✓ |
| 5 | path→Blocks; canónico NFC/slash/rel; exec; case+NFC; symlink; derived; EOL | §5.1, §5.2, §5.3 | ✓ (colisión NFC añadida; NFC solo a la key) |
| 6 | Paginación que nunca rompe Convex con 100k+ | §5.3 (B-tree determinista en Vault), §6.2 | ✓ |
| 7 | Revision un padre; lineal; head; CAS; Vault antes de Revision | §6.2, §7 | ✓ |
| 8 | Change feed (suscripción, head, diff, Blocks faltantes) | §8 | ✓ |
| 9 | Hueco GC: enumerar alcanzables desde Manifests vivos + safety | §6.3 | ✓ (grace-period + retention floor reservados) |
| 10 | Hueco zero-knowledge: capa semántica vs grafo opaco | §5.5, §6.3 | ✓ |
| 11 | Índice local: path→pcid, mtime, size, base seq, Blocks | §9 | ✓ |
| 12 | Un objeto por Block; trade-off de conteo notado | §4.2, §3 (nota), §11 (packing) | ✓ |
| 13 | Conflictos por archivo vs base común; delete-vs-edit | §7 (nivel 1), §10 (nivel 2) | ✓ |
| 14 | Primitivas concretas justificadas | §2 | ✓ |

---

### Apéndice: decisiones load-bearing nuevas para registrar en ADR

1. **`cid = BLAKE3-256(nonce || payload)`** — excluye la data key envuelta para que rotar la Space key no renombre objetos.
2. **data key y nonce DETERMINISTAS por `pcid`** derivados del **dedup secret por-Account** — habilita dedup cross-Device bajo cifrado; invierte el "data key aleatoria" de la memoria (escalado en §4.4).
3. **data key envuelta en sidecar `keys/<space_id>/<cid>`** (scoped por Space), no en el header — dimensionado correcto y rotación barata.
4. **B-tree de Manifest con paginación determinista**: orden por `casefold(NFC(p))`, `LEAF_FANOUT=256`, `INDEX_FANOUT=256`, construcción bottom-up función pura, `bk` externalizado a `blocklist/<cid>` sobre `ENTRY_INLINE_MAX=256 KiB`.
5. **Colisión por NFC tratada como conflicto**; NFC aplica solo a la key del Manifest, no al contenido ni al target de symlink.
6. **Safety de GC reservada en el protocolo**: grace-period por antigüedad + `retentionFloorSeq = min(devices.baseSeqInUse)`.
7. **`dedup` de Convex es caché, no fuente de verdad**; el dedup real vive local + HEAD al Vault.
8. **FastCDC 16/64/256 KiB con normalized chunking nivel 2** (no el 256K/1M/4M de backup): hay delta intra-archivo para código.
9. **Primitivas:** BLAKE3-256 (+ modo KDF), naming hex-lower con fan-out de 2 chars, CBOR canónico para páginas, XChaCha20-Poly1305 AEAD + wrap.