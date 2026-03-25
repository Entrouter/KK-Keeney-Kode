# KK Cryptosystem — Complete Mathematical Formulation

**John A Keeney** &nbsp;|&nbsp; IACR ePrint 2026/108500 &nbsp;|&nbsp; `kk-crypto` v0.1.0

---

## 1 &ensp; Constants & Initialisation Vector

$$N = 25, \quad R = 32, \quad R_{\text{kdf}} = 20$$

$$W_{\text{rate}} = 19, \quad W_{\text{cap}} = 6, \quad B_{\text{rate}} = 8 \cdot W_{\text{rate}} = 152$$

$$\delta_H = \text{0x01}, \quad \delta_K = \text{0x02}, \quad \delta_M = \text{0x03}$$

$$\text{IV}[i] = \left\lfloor \operatorname{frac}\!\left(\sqrt{p_i}\right) \cdot 2^{64} \right\rfloor, \quad i \in \{0, \dots, 24\}, \quad p_i = i\text{-th prime}$$

$$\rho = \bigl(\rho_0, \rho_1, \dots, \rho_{14}\bigr) \in \bigl(\{1,3,\dots,63\}^2\bigr)^{15} \quad \text{(15 rotation pairs, all odd)}$$

$$D_k = \text{DIAGS}[k] \subset \{0,\dots,24\}, \quad |D_k| = 5, \quad k \in \{0,\dots,4\}$$

---

## 2 &ensp; Core Primitives

**MFR** (Multiply-Fold-Rotate):

$$\operatorname{MFR}(a, b, r): \quad p = a \cdot (b \mid 1) \bmod 2^{64}, \quad \operatorname{MFR} = \operatorname{ROL}_{r}\!\bigl(p \oplus (p \gg 32)\bigr)$$

**DDR** (Data-Dependent Rotation):

$$\operatorname{DDR}(a, b): \quad f = b \oplus (b \gg 32), \quad s = \bigl(f \oplus (f \gg 16) \oplus (f \gg 8)\bigr) \;\&\; 63, \quad \operatorname{DDR} = \operatorname{ROL}_{s}(a)$$

**Quintet round** on words $(a,b,c,d,e)$ with rotation pair $(\rho_0, \rho_1)$:

$$a \leftarrow \operatorname{MFR}(a,\, b,\, \rho_0)$$

$$c \leftarrow c \oplus a$$

$$d \leftarrow \operatorname{DDR}(d,\, c)$$

$$e \leftarrow \operatorname{MFR}(e,\, d,\, \rho_1)$$

$$b \leftarrow b \oplus e$$

---

## 3 &ensp; Permutation $\pi$

For round $r \in \{0, \dots, R\!-\!1\}$, state $S \in \{0,1\}^{64 \times 25}$ on a $5 \times 5$ grid:

**Phase 1 — Rows** $(j = 0 \dots 4)$:

$$\bigl(S[5j],\; S[5j\!+\!1],\; S[5j\!+\!2],\; S[5j\!+\!3],\; S[5j\!+\!4]\bigr) \leftarrow \operatorname{Quintet}\!\bigl(\cdots,\; \rho_j\bigr)$$

**Phase 2 — Columns** $(j = 0 \dots 4)$:

$$\bigl(S[j],\; S[j\!+\!5],\; S[j\!+\!10],\; S[j\!+\!15],\; S[j\!+\!20]\bigr) \leftarrow \operatorname{Quintet}\!\bigl(\cdots,\; \rho_{5+j}\bigr)$$

**Phase 3 — Diagonals** $(k = 0 \dots 4)$:

$$\bigl(S[D_k[0]],\; \dots,\; S[D_k[4]]\bigr) \leftarrow \operatorname{Quintet}\!\bigl(\cdots,\; \rho_{10+k}\bigr)$$

**Round-constant injection** (grid corners + centre):

$$S[0] \mathrel{+}= r, \quad S[4] \mathrel{+}= r \cdot \phi, \quad S[12] \mathrel{+}= r \cdot e', \quad S[20] \mathrel{+}= r \cdot \pi', \quad S[24] \mathrel{+}= r \cdot c_4$$

where $\phi = \text{0x9E3779B97F4A7C15}$, $e' = \text{0xB7E151628AED2A6A}$, $\pi' = \text{0x243F6A8885A2F7A4}$, $c_4 = \text{0x298B075B4B6A5240}$, all $\bmod 2^{64}$.

**Re-keying** (when $r \bmod 8 = 7$):

$$S[i] \leftarrow S[i] \oplus \operatorname{ROL}_{r}\!\bigl(S[W_{\text{rate}} + (i \bmod W_{\text{cap}})]\bigr), \quad i \in \{0, \dots, W_{\text{rate}}\!-\!1\}$$

---

## 4 &ensp; Sponge Construction

**Initialise:** $\; S \leftarrow \text{IV},\; \text{rotations } \rho$

**Absorb** block $B$ (zero-padded to $W_{\text{rate}}$ words):

$$S[i] \leftarrow S[i] \oplus B_i \quad (i = 0 \dots W_{\text{rate}}\!-\!1), \qquad S \leftarrow \pi_R(S)$$

**Finalize** with domain byte $\delta$:

$$\text{pad} = [\delta,\; \text{0x80},\; 0, \dots, 0,\; \text{0x01}] \quad (B_{\text{rate}} \text{ bytes}), \qquad \text{Absorb}(\text{pad})$$

**Squeeze** $n$ bytes (full $R = 32$ rounds):

$$\text{output} \leftarrow \text{output} \;\|\; S[0 \dots W_{\text{rate}}\!-\!1], \qquad S \leftarrow \pi_R(S), \qquad \text{repeat until } n \text{ bytes emitted}$$

**Squeeze-KDF** $n$ bytes (reduced $R_{\text{kdf}} = 20$ rounds):

$$\text{Same, with } S \leftarrow \pi_{R_{\text{kdf}}}(S)$$

---

## 5 &ensp; Hash, MAC, KDF

$$\operatorname{KK\text{-}Hash}(M): \quad \text{Absorb}(M) \to \text{Finalize}(\delta_H) \to \text{Squeeze}(32)$$

$$\operatorname{KK\text{-}MAC}(K, M): \quad \text{Absorb}(K) \to \text{Absorb}(M) \to \text{Finalize}(\delta_M) \to \text{Squeeze}(32)$$

$$\operatorname{KK\text{-}MAC}_\varepsilon(K, M, \varepsilon): \quad \text{Absorb}(K) \to \text{Absorb}(\varepsilon) \to \text{Absorb}(M) \to \text{Finalize}(\delta_M) \to \text{Squeeze}(32)$$

$$\operatorname{KK\text{-}KDF}(s, \mathrm{salt}, \mathrm{info}, n): \quad \text{Absorb}(s) \to \text{Absorb}(\mathrm{salt}) \to \text{Absorb}(\mathrm{info}) \to \text{Finalize}(\delta_K) \to \text{Squeeze-KDF}(n)$$

---

## 6 &ensp; Entropy

**Gather** $\to \varepsilon = (\varepsilon_b,\, \varepsilon_t)$ where $\varepsilon_b \in \{0,1\}^{256}$, $\varepsilon_t \in \{0,1\}^{128}$:

$$s_0 = \text{OsRng}(32), \quad s_1 = \text{timestamp}\_\text{nanos}\_\text{LE}(16)$$

$$s_2 = (\text{rdtsc} \oplus \text{stack}\_\text{addr})_{\text{LE}(8)}, \quad s_3 = \operatorname{KK\text{-}Hash}(\text{jitter}_{64})(32)$$

$$\varepsilon_b = \operatorname{kk\_entropy\_mix}(\{s_0, s_1, s_2, s_3\},\, 32), \qquad \varepsilon_t = \text{timestamp at capture}$$

**kk\_entropy\_mix** $(\{s_0, \dots, s_{m-1}\},\, n)$:

$$\text{Init sponge } S, \quad \text{for } i = 0 \dots m\!-\!1: \; \text{Absorb}\!\bigl(i_{\text{LE}(8)} \| \operatorname{len}(s_i)_{\text{LE}(8)} \| s_i\bigr)$$

$$\text{Finalize}(\delta_H) \to \text{Squeeze}(n)$$

**Serialise:** $\; \operatorname{ser}(\varepsilon) = \varepsilon_b \;\|\; (\varepsilon_t)_{\text{LE}(16)} \quad (48 \text{ bytes})$

---

## 7 &ensp; Symbol & Commitment Key Derivation

$$K_{\text{sym}}(K, j, t) = \operatorname{KK\text{-}KDF}\!\Bigl(K,\; \emptyset,\; \text{``KK-sym-v1''} \| \text{0x00} \| j_{\text{LE}(8)} \| t_{\text{LE}(16)},\; B_{\text{rate}}\Bigr)$$

$$K_{\text{commit}}(K, \varepsilon) = \operatorname{KK\text{-}KDF}\!\bigl(K,\; \varepsilon_b,\; \text{``KK-commit-v1''},\; 32\bigr)$$

**Batch** (8 consecutive indices, vectorised):

$$\bigl(K_{\text{sym}}^{(j)}, \dots, K_{\text{sym}}^{(j+7)}\bigr) = \operatorname{KK\text{-}KDF\text{-}Batch}_8\!\bigl(K, j, t\bigr)$$

---

## 8 &ensp; XOR Keystream Encryption

$$\text{CHUNK} = 4096, \quad \text{BATCH} = 8 \cdot \text{CHUNK} = 32768$$

$$P = P_0 \| P_1 \| \cdots \| P_{\lceil L / \text{CHUNK} \rceil - 1}$$

**Full 8-chunk batches** (parallel):

$$\bigl(K_{\text{sym}}^{(8i)}, \dots, K_{\text{sym}}^{(8i+7)}\bigr) \leftarrow \operatorname{Batch}_8(K, 8i, \varepsilon_t)$$

$$C_{8i+k} = P_{8i+k} \oplus K_{\text{sym}}^{(8i+k)}\bigl[0 \dots |P_{8i+k}|\!-\!1\bigr], \quad k = 0 \dots 7$$

**Tail chunks** (scalar):

$$K_{\text{sym}}^{(j)} \leftarrow K_{\text{sym}}(K, j, \varepsilon_t), \quad C_j = P_j \oplus K_{\text{sym}}^{(j)}\bigl[0 \dots |P_j|\!-\!1\bigr]$$

---

## 9 &ensp; Temporal Commitment

**Standard:**

$$K_c = K_{\text{commit}}(K, \varepsilon), \quad \tau = \operatorname{KK\text{-}MAC}\!\bigl(K_c,\; \varepsilon_b \| (\varepsilon_t)_{\text{LE}} \| C\bigr)$$

**AEAD:**

$$\tau = \operatorname{KK\text{-}MAC}\!\bigl(K_c,\; |A|_{\text{LE}(8)} \| A \| \varepsilon_b \| (\varepsilon_t)_{\text{LE}} \| C\bigr)$$

**Bound** (temporal proof, 96 bytes):

$$\tau = \operatorname{KK\text{-}MAC}_\varepsilon\!\bigl(K_c,\; \nu \| \tau_{\text{prev}} \| \varepsilon_b \| (\varepsilon_t)_{\text{LE}} \| C,\; \varepsilon_b\bigr)$$

$$\text{TemporalProof} = \nu(32) \;\|\; \varepsilon_b(32) \;\|\; \tau(32)$$

---

## 10 &ensp; Encode / Decode

**Encode** $(K, P)$:

$$\varepsilon \leftarrow \text{Gather}(), \quad C \leftarrow P \oplus \text{Keystream}(K, \varepsilon), \quad \tau \leftarrow \text{Commit}(K, \varepsilon, C)$$

$$\text{return } \bigl(\operatorname{ser}(\varepsilon),\; C,\; \tau\bigr)$$

**Decode** $(K, \operatorname{ser}(\varepsilon), C, \tau)$:

$$\text{verify } \tau, \quad P \leftarrow C \oplus \text{Keystream}(K, \varepsilon)$$

**Encode-AEAD** $(K, P, A)$: same with $\text{Commit}_{\text{aead}}$

**Encode-Bound** $(K, P, \nu, \tau_{\text{prev}})$: same with $\text{Commit}_{\text{bound}}$

---

## 11 &ensp; KkRng — Deterministic Generator

$$\text{Init}(\text{seed}): \quad \sigma_0 = \operatorname{KK\text{-}Hash}(\text{seed})$$

$$\text{Next}(n): \quad \text{out} = \operatorname{KK\text{-}KDF}(\sigma_i,\, \emptyset,\, \text{``KkRng-next''},\, n), \quad \sigma_{i+1} = \operatorname{KK\text{-}Hash}(\sigma_i)$$

$$\text{Reseed}(z): \quad \sigma \leftarrow \operatorname{KK\text{-}Hash}(\sigma \| z)$$

---

## 12 &ensp; EKA — Ephemeral Key Agreement (3-message, PSK)

$$\varepsilon_A \leftarrow \text{Gather}(), \quad \varepsilon_B \leftarrow \text{Gather}()$$

**Message 1** (Alice $\to$ Bob, 32 B):

$$m_1 = \operatorname{KK\text{-}Hash}\!\bigl(\operatorname{ser}(\varepsilon_A)\bigr)$$

**Message 2** (Bob $\to$ Alice, 80 B):

$$m_2 = \operatorname{ser}(\varepsilon_B) \;\|\; \operatorname{KK\text{-}MAC}\!\bigl(\text{psk},\; \operatorname{ser}(\varepsilon_B) \| m_1\bigr)$$

**Message 3** (Alice $\to$ Bob, 80 B):

$$m_3 = \operatorname{ser}(\varepsilon_A) \;\|\; \operatorname{KK\text{-}MAC}\!\bigl(\text{psk},\; \operatorname{ser}(\varepsilon_A) \| \operatorname{ser}(\varepsilon_B)\bigr)$$

**Bob verifies:**

$$\operatorname{KK\text{-}Hash}\!\bigl(\operatorname{ser}(\varepsilon_A)\bigr) \stackrel{?}{=} m_1 \quad \wedge \quad \text{verify } \operatorname{auth}_A$$

**Session key:**

$$K_{\text{sess}} = \operatorname{KK\text{-}KDF}\!\bigl(\text{psk},\; \operatorname{ser}(\varepsilon_A) \| \operatorname{ser}(\varepsilon_B),\; \text{``KK-EKA-session''},\; 32\bigr)$$

---

## 13 &ensp; ROPE — 4-Strand Ratchet

**Init** $(K, \text{ctx})$:

$$\text{salt} = \operatorname{KK\text{-}Hash}(\text{ctx})$$

$$\sigma_{\text{ent}} = \operatorname{KK\text{-}KDF}(K,\, \text{salt},\, \text{``KK-rope-init-ent''},\, 32)$$

$$\sigma_{\text{tmp}} = \operatorname{KK\text{-}KDF}(K,\, \text{salt},\, \text{``KK-rope-init-tmp''},\, 32)$$

$$\sigma_{\text{chn}} = \operatorname{KK\text{-}KDF}(K,\, \text{salt},\, \text{``KK-rope-init-chn''},\, 32)$$

$$n = 0$$

**Step** $(\varepsilon)$:

$$\sigma_{\text{ent}}' = \operatorname{KK\text{-}KDF}(\sigma_{\text{ent}},\; \varepsilon_b,\; \text{``KK-rope-ent-v1''},\; 32)$$

$$\sigma_{\text{tmp}}' = \operatorname{KK\text{-}KDF}(\sigma_{\text{tmp}},\; (\varepsilon_t)_{\text{LE}(16)},\; \text{``KK-rope-tmp-v1''},\; 32)$$

$$n \leftarrow n + 1, \quad \sigma_{\text{chn}}' = \operatorname{KK\text{-}KDF}(\sigma_{\text{chn}},\; n_{\text{LE}(8)},\; \text{``KK-rope-chn-v1''},\; 32)$$

$$\text{combined}(104) = \sigma_{\text{ent}}' \;\|\; \sigma_{\text{tmp}}' \;\|\; \sigma_{\text{chn}}' \;\|\; n_{\text{LE}(8)}$$

$$\text{out}(64) = \operatorname{KK\text{-}KDF}(\text{combined},\; \varepsilon_b,\; \text{``KK-rope-mix-v1''},\; 64)$$

$$\sigma_{\text{chn}} \leftarrow \text{out}[0\!\dots\!31], \quad K_{\text{msg}} = \text{out}[32\!\dots\!63]$$

**Session encode / decode:**

$$\text{Encode}_{\text{session}}(P): \quad K_{\text{msg}} \leftarrow \text{Step}(\text{Gather}()), \quad \text{return } \text{Encode}(K_{\text{msg}}, P)$$

$$\text{Decode}_{\text{session}}(\text{step}, \text{pkt}): \quad K_{\text{msg}} \leftarrow \text{Step}(\text{step}.\varepsilon), \quad \text{return } \text{Decode}(K_{\text{msg}}, \text{pkt})$$

---

## 14 &ensp; BB84 QKD Module

$$n = 4096, \quad \theta_{\text{eve}} = 0.10, \quad f_{\text{check}} = 0.25$$

**Alice prepares** $\forall\, i \in \{0,\dots,n\!-\!1\}$:

$$b_i \xleftarrow{R} \{0,1\}, \quad \beta_i^A \xleftarrow{R} \{+, \times\}, \quad q_i = \text{encode}(b_i, \beta_i^A)$$

**Eve intercepts** (optional):

$$\beta_i^E \xleftarrow{R} \{+, \times\}, \quad \hat{b}_i^E = \text{measure}(q_i, \beta_i^E), \quad q_i' = \text{re-prepare}(\hat{b}_i^E, \beta_i^E)$$

**Bob measures:**

$$\beta_i^B \xleftarrow{R} \{+, \times\}, \quad \hat{b}_i^B = \text{measure}(q_i, \beta_i^B)$$

**Sifting:**

$$\mathcal{S} = \{i : \beta_i^A = \beta_i^B\}, \quad |\mathcal{S}| \ge 64$$

**Error estimation:**

$$\mathcal{C} \subset \mathcal{S}, \quad |\mathcal{C}| = \lfloor f_{\text{check}} \cdot |\mathcal{S}| \rfloor, \quad e = \frac{|\{i \in \mathcal{C} : b_i \ne \hat{b}_i^B\}|}{|\mathcal{C}|}$$

$$e > \theta_{\text{eve}} \implies \text{abort}$$

**Privacy amplification:**

$$K_{\text{qkd}} = \operatorname{KK\text{-}KDF}\!\bigl((b_i)_{i \in \mathcal{S} \setminus \mathcal{C}},\; \text{``BB84-KK-v1''},\; \text{``KK-QKD-shared-key''},\; 32\bigr)$$

**QKD-secured $\varepsilon$ transport:**

$$\text{mask} = \operatorname{KK\text{-}KDF}\!\bigl(\text{``QKD-epsilon-transport''},\; K_{\text{qkd}},\; \text{``KK-QKD-epsilon-v1''},\; 48\bigr)$$

$$\text{Encrypt}_\varepsilon(\varepsilon) = \operatorname{ser}(\varepsilon) \oplus \text{mask}, \qquad \text{Decrypt}_\varepsilon(c) = c \oplus \text{mask}$$

---

$\square$
