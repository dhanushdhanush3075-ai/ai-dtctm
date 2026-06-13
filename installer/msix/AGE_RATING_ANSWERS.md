# AI-DTCTM — IARC Age Rating Questionnaire Pre-filled Answers

The Microsoft Store uses the **IARC** (International Age Rating Coalition)
questionnaire. It's ~35 questions across 6 categories. Below is the exact
set of answers to give for AI-DTCTM. Expected outcome: **Everyone 3+**
(Developer Tools, no violence/gambling/NSFW).

Total time to complete the IARC questionnaire: ~10 minutes.

---

## Section 1 — Violence

| # | Question | Answer |
|---|---|---|
| 1 | Does the app depict realistic-looking violence? | **No** |
| 2 | Does the app depict cartoon or fantasy violence? | **No** |
| 3 | Does the app depict any animated blood or gore? | **No** |
| 4 | Does the app simulate any kind of weapon use? | **No** |
| 5 | Does the app reference real-world weapons? | **No** |
| 6 | Does the app glorify or reward violence? | **No** |
| 7 | Does the app contain depictions of torture? | **No** |

---

## Section 2 — Sexuality / Nudity

| # | Question | Answer |
|---|---|---|
| 1 | Does the app contain nudity? | **No** |
| 2 | Does the app contain sexual references? | **No** |
| 3 | Does the app contain dating or romance content? | **No** |
| 4 | Does the app contain any provocative themes? | **No** |

---

## Section 3 — Crude humor / Language

| # | Question | Answer |
|---|---|---|
| 1 | Does the app contain profanity? | **No** |
| 2 | Does the app contain crude humor? | **No** |
| 3 | Does the app contain bathroom humor? | **No** |

---

## Section 4 — Substances

| # | Question | Answer |
|---|---|---|
| 1 | Does the app reference or depict alcohol use? | **No** |
| 2 | Does the app reference or depict tobacco use? | **No** |
| 3 | Does the app reference or depict drug use? | **No** |
| 4 | Does the app simulate or encourage substance use? | **No** |

---

## Section 5 — Gambling

| # | Question | Answer |
|---|---|---|
| 1 | Does the app simulate gambling? | **No** |
| 2 | Does the app contain real-money gambling? | **No** |
| 3 | Does the app contain in-app purchases? | **No** |
| 4 | Does the app contain loot boxes? | **No** |

---

## Section 6 — Online interaction

| # | Question | Answer |
|---|---|---|
| 1 | Does the app allow users to communicate with each other? | **No** (cloud-sync sync between same user's devices doesn't count) |
| 2 | Does the app share location with other users? | **No** |
| 3 | Does the app allow exchange of user-generated content? | **No** |
| 4 | Does the app allow purchases between users? | **No** |
| 5 | Does the app contain unmonitored user-generated content? | **No** |

---

## Section 7 — Personally Identifying Info & Privacy

| # | Question | Answer |
|---|---|---|
| 1 | Does the app collect personal information from users? | **Only locally** (username, email — never transmitted) |
| 2 | Does the app share user data with third parties? | **No** |
| 3 | Does the app track user location? | **No** |
| 4 | Does the app access user's contacts / camera / microphone? | **No** |

---

## Section 8 — Security tools disclosure

(Microsoft Store treats security tools as a separate category — these
questions appear if you marked your app as "Developer tools → Security")

| # | Question | Answer |
|---|---|---|
| 1 | Does the app perform penetration testing? | **Yes** (against user's own Docker-isolated copies) |
| 2 | Does the app handle malware samples? | **Yes** (EICAR test string only — not real malware) |
| 3 | Does the app require admin/root privileges? | **No** (runs as standard user) |
| 4 | Does the app modify system files? | **No** |
| 5 | Does the app install kernel-mode drivers? | **No** |
| 6 | Does the app bypass any Windows security feature? | **No** (respects WDAC, SmartScreen, Defender) |

---

## Expected outcome

After submitting, IARC will return:
- **ESRB**: Everyone (3+)
- **PEGI**: 3
- **USK**: 0
- **CERO**: A
- **GRAC**: All

This is the lowest possible rating — appropriate for a security education tool.

---

## If asked for justification

If Microsoft reviewer asks why a "security testing" app is rated 3+:

> The app performs only **defensive analysis** (malware detection,
> vulnerability scanning) and **educational offensive testing** in fully
> isolated, automatically-destroyed Docker containers. No real malware is
> bundled — only the official EICAR test string, which is a 68-byte
> harmless industry-standard antivirus test file. The app contains no
> violence, sexual content, or other age-inappropriate material.
