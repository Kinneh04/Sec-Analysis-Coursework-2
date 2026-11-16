# Chat Export: SecureAge, Bkav Pro, and Symantec False Positives

**Exported:** 31 October 2026  
**Scope:** User messages and assistant research responses in this conversation.  
**Note:** Interactive charts, image widgets, and internal source reference identifiers have been converted into Markdown text. Numerical findings reflect the original conversation and have not been independently revalidated in this export.

---

## User

do a deep research on secureage and their false positive

## Assistant — SecureAge Antivirus: False-Positive Research Report

**Research date:** 31 October 2026  
**Focus:** SecureAge APEX, VirusTotal detections, SecureAPlus and CatchPulse

### Executive summary

**There is credible evidence that SecureAge produces false positives, including on apparently legitimate Windows applications.** Historical independent testing provides measurable evidence of false-positive behavior.

AV-Comparatives' October 2018 evaluation of the SecureAge APEX engine reported a **0.7% false-positive rate** on 1,000 benign files. More recent public reports show SecureAge as the only antivirus engine detecting certain software distributions.

However, it would be inaccurate to conclude that SecureAge has a 0.7% false-positive rate today. That result is eight years old, tested a particular engine configuration, and cannot be generalized to its current products.

| Metric | Result | Context |
|---|---:|---|
| APEX false-positive rate (2018) | 0.7% | 7/1,000 clean files |
| APEX malware detection (2018) | 86.8% | 868/1,000 malicious files |
| SecureAPlus Pro false-positive rate (April 2021) | 0.005% | Virus Bulletin VB100 |
| Recent public report | October 2026 | SecureAge-only detection reported on GitHub |

**Overall assessment**

| Question | Finding |
|---|---|
| Does SecureAge generate false positives? | Yes, demonstrated in independent testing. |
| Are there recent public reports? | Yes, including 2025–2026 examples. |
| Does it use machine learning? | Yes, its APEX engine is described as deep-learning-based. |
| Is SecureAge unreliable in every situation? | Not established. |
| Should a SecureAge-only VirusTotal detection be considered proof of malware? | No. |
| Is its current false-positive rate known? | Not from the public tests identified. |

### 1. What exactly is SecureAge?

SecureAge Technology develops multiple security products. A detection labelled `SecureAge` on VirusTotal is not equivalent to a complete detection verdict from its endpoint security platform.

- **SecureAge APEX:** Machine-learning malware detection engine designed to identify malicious files using patterns learned during training, not exclusively signatures.
- **SecureAPlus:** Security product combining application allowlisting, antivirus scanning, and cloud-based multi-engine analysis.
- **CatchPulse:** Endpoint protection offering combining application control, AI detection, and more than ten cloud antivirus engines.

Three separate things require evaluation: APEX's standalone detection accuracy, false-positive behavior of the complete endpoint product, and allowlisting blocks of otherwise benign applications.

### 2. Independent testing

#### 2.1 AV-Comparatives, October 2018

The independent APEX test used a configuration intended for VirusTotal integration.

| Test property | Configuration |
|---|---|
| Product | SecureAge APEX |
| Model version | 4.1 |
| Sensitivity | High (level 2) |
| Execution | Offline |
| Other AV engines | Disabled |
| Benign samples | 1,000 |
| Malware samples | 1,000 |
| False positives | **7** |
| Malware detected | **868** |

The engine missed 13.2% of the malicious test files and incorrectly classified 0.7% of the clean test files as malicious. The relatively small benchmark and high-sensitivity setting limit generalization. SecureAge documentation acknowledges that higher APEX sensitivity produces more false alarms.

Source: [AV-Comparatives APEX Engine Test (2018)](https://www.secureaplus.com/wp-content/uploads/2019/04/AV-Comparatives-APEX-Test.pdf).

#### 2.2 Virus Bulletin VB100, 2020–2021

Virus Bulletin tested the complete SecureAPlus Pro product, not just standalone APEX.

| Test date | SecureAPlus Pro false-positive rate | WildList detection |
|---|---:|---:|
| June 2020 | 0.001% | 99.7% |
| August 2020 | 0.009% | 99.8% |
| October 2020 | 0.001% | 99.7% |
| April 2021 | 0.005% | 99.8% |

These values are substantially lower than the 2018 standalone APEX result. The tests used different configurations, sample sets, sensitivity settings, and product components. In April 2021, Avast Free Antivirus and AVG Internet Security recorded reported 0.000% false-positive rates versus SecureAPlus Pro's 0.005%.

Source: [Virus Bulletin VB100 April 2021](https://www.virusbulletin.com/virusbulletin/2021/04/vb100-certification-report/).

#### 2.3 Certification failures

SecureAge did not achieve VB100 certification in several instances:

- April 2020: regular and offline SecureAge Plus Pro configurations were listed as not certified.
- June, August, October 2020: offline configuration listed as not certified.
- February 2021: SecureAPlus Pro listed as not certified.

These failures should not automatically be attributed to false positives: VB100 certification also requires sufficient malware detection. Historical testing results were mixed.

### 3. Real-world false-positive reports

These are reports from users/developers, not controlled proof that every file was benign.

#### Case A: AvastUI.exe (August 1, 2025)

A community user reported SecureAge identifying `AvastUI.exe` as malicious, with **1/71 engines** detecting. Reinstalling Avast reportedly did not resolve it. If the executable was authentic and unchanged, it would be a strong false-positive example, but the discussion does not independently establish integrity.

- [Avast community report](https://community.avast.com/t/virus-total-flag-avastui-exe/891509)
- [VirusTotal file](https://www.virustotal.com/gui/file/fffa4d313ed1edc91a170908ddc2326c1b818a9a648142f4d48a6704cfc8f96f)

#### Case B: KeyEcho installer (December 22, 2025)

The unsigned `KeyEcho_0.0.5_arm64-setup.exe` reportedly received **3/72 detections**: SecureAge, Arctic Wolf, and DeepInstinct. The issue author attributed the detections to heuristic/ML classification of keyboard-hook functionality and lack of signing. The maintainer later confirmed Authenticode signing in version 1.0, without proof that the earlier SecureAge verdict was corrected.

- [GitHub issue #43](https://github.com/ZacharyL2/KeyEcho/issues/43)
- [VirusTotal file](https://www.virustotal.com/gui/file/f59331c16aafd343a935ab763e1984f58ae18910ff31b89e60de777369c7e5b3)

#### Case C: DeepSeek Harness Windows executable (October 3, 2026)

A user reported SecureAge as the sole detecting engine (**1/50**) on `dsh-latest-windows-x64.exe`. The discussion included the SHA-256 and VirusTotal link, without independent confirmation of provenance. The question was reportedly unanswered when reviewed.

- [GitHub discussion #8731](https://github.com/deepseek-ai/deepseek-harness/discussions/8731)
- [VirusTotal file](https://www.virustotal.com/gui/file/d61cd8882f8b8a1251144320493ad27920d15139503eba2465b9579eee720cfc)

These cases support investigation but do not establish a population-wide false-positive rate.

### 4. Why might SecureAge generate false positives?

#### 4.1 ML generalization

Benign programs can resemble malware statistically without being malicious. Potential signals in static malware classification include unusual PE sections, high-entropy data, dynamic loading, compressed application components, low-prevalence executables, and dual-use APIs. SecureAge does not publicly document enough details to assert that APEX uses all of these specific features.

#### 4.2 Sensitivity settings

SecureAge's CatchPulse documentation (June 2026) describes:

| Sensitivity | Documented trade-off |
|---|---|
| Low | Fewer false alarms, potentially lower detection |
| Medium | Recommended balance |
| High | Higher detection, potentially more false alarms |

The 2018 APEX benchmark used **High** sensitivity, so its results should not be attributed to every setting.

- [SecureAge sensitivity documentation](https://knowledgebase.secureage.com/secureagecentral/Content/policy/settings.htm)

#### 4.3 A block is not always an antivirus false positive

| Outcome | Classification |
|---|---|
| APEX identifies known-clean executable as malware | Antivirus false positive |
| Unknown executable needs administrator approval | Allowlisting block |
| Another cloud AV engine identifies a clean file as malware | Third-party false positive |
| Program blocked under an explicit security policy | Policy enforcement |

### 5. How much to trust a SecureAge-only VirusTotal detection?

Treat a SecureAge-only finding as **a low-confidence alert requiring corroboration**, not proof of maliciousness. A sole detection can still be correct for new threats.

Triage:
1. Verify original source, SHA-256, and signature.
2. Review other vendor verdicts, file metadata, and static indicators.
3. If official provenance and integrity are established with no corroborating indicators, consider likely false positive.
4. If origin is unverified or suspicious evidence exists, investigate further.

VirusTotal recommends reanalysis and contacting the detecting vendor for suspected false positives.

### 6. Reporting false positives to SecureAge

Use [SecureAge contact / false-positive reporting](https://www.secureage.com/contact-us). Include SHA-256, detection label, provenance, expected behavior, VirusTotal link, and any verified signature/release checksum. SecureAge's older SecureAPlus documentation recommends a compressed copy of the file and warns that corrections may take time.

### 7. What is still unknown?

- Current 2025–2026 standalone VirusTotal-engine false-positive rate.
- Population-wide error rate on representative clean software.
- Internal model features and thresholds producing specific detections.
- Whether/how quickly each reported detection was corrected.
- Whether SecureAge is currently worse than competing ML engines.

Anecdote searches overrepresent failures because correct benign classifications rarely prompt public posts.

### 8. Recommended independent experiment

Use several hundred verified clean executable files from trusted publishers, mixing signed and unsigned programs. Record SecureAge results, other engines, and independently validated ground truth. Track signing status, installer vs ordinary executable, disagreement, file features, and rescans.

**False-positive rate:** `FPR = FP / (FP + TN)`.

A clean-only set measures false positives, not precision, recall, or overall malware-detection quality; those require malicious samples too.

### SecureAge conclusion

- **High confidence:** APEX and SecureAPlus Pro have recorded false positives in historical independent testing.
- **Moderate confidence:** Recent credible public reports of suspected false positives exist.
- **Insufficient evidence:** SecureAge has an unusually high false-positive rate in 2026 relative to its competitors.

Further reading:
- [AV-Comparatives — APEX Engine Test (2018)](https://www.secureaplus.com/wp-content/uploads/2019/04/AV-Comparatives-APEX-Test.pdf)
- [Virus Bulletin — April 2021](https://www.virusbulletin.com/virusbulletin/2021/04/vb100-certification-report/)
- [TechRadar — SecureAPlus Lite Review](https://www.techradar.com/reviews/secureaplus-lite-for-windows)
- [SecureAge sensitivity settings](https://knowledgebase.secureage.com/secureagecentral/Content/policy/settings.htm)
- [SecureAge contact](https://www.secureage.com/contact-us)

---

## User

what about bkav_pro and symantec

## Assistant — Bkav Pro vs Symantec vs SecureAge: False-Positive Analysis

**Bkav Pro has documented suspected false positives on legitimate software, including a case where the detection disappeared after a rescan. Symantec also produces false positives, but has an established enterprise remediation process.** Neither has a publicly verified 2026 false-positive rate directly comparable to SecureAge's standalone VirusTotal engine.

### 1. Side-by-side comparison

| Category | Bkav Pro | Symantec | SecureAge |
|---|---|---|---|
| VirusTotal engine | `Bkav Pro` | `Symantec` | `SecureAge` |
| False positives documented | Yes | Yes | Yes |
| Recent public examples | Yes | Yes, vendor-documented | Yes |
| 2026 independently measured VT-engine FP rate | Not established | Not established | Not established |
| Sole-engine detections | Observed | Possible | Observed |
| Recommended interpretation of sole detection | Investigate | Investigate | Investigate |

VirusTotal lists Bkav Pro and Symantec separately and warns that VT integrations can differ from commercial endpoint products.

- [VirusTotal contributors](https://docs.virustotal.com/docs/contributors)

### 2. Bkav Pro: Evidence of false positives

Bkav Pro is noteworthy for public reports of `W64.AIDetectMalware` alerts on otherwise legitimate software.

#### Case A — Rnote (February 2025)

A GitHub issue documented Bkav Pro flagging the official Windows installer for Rnote version 0.11.0:

- File: `rnote-win-installer-0.11.0-x86_64.exe`
- SHA-256: `3c71b399a21eb6d7eb5137d2cdbedb5f7e7639924d45168d0bb6a18d45d42768`
- Reportedly the official release installer.

The issue was closed, but the indexed thread does not establish whether Bkav corrected the verdict or why the issue was closed.

- [Rnote GitHub issue #1353](https://github.com/flxzt/rnote/issues/1353)

#### Case B — RustDesk (2026)

A RustDesk discussion reported a properly signed x64 build getting a sole Bkav Pro detection:

| Moment | VirusTotal result | Bkav Pro verdict |
|---|---|---|
| Initial scan | 1/72 | `W64.AIDetectMalware` |
| Later rescan | 0/71 | Undetected |

The author reported the detection disappearing for the same SHA-256 without modifying the executable. The reason for the verdict change was not verified.

- [RustDesk discussion #13770](https://github.com/rustdesk/rustdesk/discussions/13770)

**Implication:** A historical single-engine VirusTotal snapshot may not be stable over time.

### 3. Symantec: Evidence and caveats

Symantec, an enterprise security brand owned by Broadcom, acknowledges that heuristic, behavioral, and reputation-based protection can misclassify legitimate applications.

Broadcom's exclusion guidelines, updated June 3, 2026, discuss false-positive risks including:

- `Bloodhound.SONAR.*`
- `SONAR.*`
- `Suspicious.*`
- Proactive Threat Protection alerts

They note potential disruptions to unfamiliar, internally developed or business-critical applications. Broadcom also describes the IRON reputation whitelist for confirmed SONAR and Download Insight false positives, distributed through definition updates.

No current independent false-positive rate for the exact `Symantec` VirusTotal engine was verified in the discussion. Symantec Endpoint Protection was not among the 16 products evaluated in AV-Comparatives' March–June 2026 enterprise test, and Norton benchmarks cannot necessarily be substituted: the 2026 report states that the tested Norton product used the Avast engine.

### 4. Weighting VirusTotal detections

| Scenario | Suggested interpretation |
|---|---|
| Bkav Pro only: `W64.AIDetectMalware` | Low-confidence signal; investigate |
| SecureAge only: generic ML threat | Low-confidence signal; investigate |
| Symantec only: generic heuristic threat | Investigate; not proof of maliciousness |
| Symantec reports a specific malware-family signature | Potentially stronger lead; independently verify |
| Bkav Pro + SecureAge | Corroboration, though benign features can trip both |
| Symantec + Microsoft + ESET with consistent findings | Stronger reason to investigate when file evidence supports it |

These are qualitative triage guidelines, **not calibrated probabilities**. A legitimate PyInstaller application, for example, might draw multiple heuristic detections due to its packaging rather than malicious activity.

### 5. Reporting false positives

- **Symantec / Broadcom:** [SymSubmit official portal](https://symsubmit.symantec.com/).
- **Bkav Pro:** Check the contact information in [VirusTotal's official contributors directory](https://docs.virustotal.com/docs/contributors).

VirusTotal does not independently remove third-party detection verdicts; the vendor must change its classification before a new scan reflects it.

### Final conclusion

- **Bkav Pro:** Public suspected false positives documented; one RustDesk detection disappeared for an unchanged hash after a rescan.
- **Symantec:** Vendor acknowledges false positives and offers remediation. Its current VirusTotal-specific false-positive rate remains unverified.
- **SecureAge:** Historical independent measurements and contemporary reports exist; no reliable current comparative false-positive rate established.

If **Bkav Pro, SecureAge, and Symantec are the only three engines identifying a file as malicious**, that alone is not enough to classify the file as malware. The exact detection labels, file origin, digital signing, import tables, and other corroborating evidence matter.

**Research takeaway:** None of these three vendors should be treated as definitive alone, and the available research does not support a numerical ranking of their 2026 false-positive rates.

---

## User

can u export this chat into a markdown

