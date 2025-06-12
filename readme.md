# 💀 Code Critique & Full Leak.

> Leaking this because a "Malware Analyst" can't secure his code properly and doesn't provide source code to some bs.

Anyways! Honest code critiques, here we go:

---

<details>
<summary>Security and Execution</summary>

- The initial program downloads and runs unsigned `.exe` files from a GitHub link. These can easily be replaced by the author.  
- No execution confirmation.  
- YARA rule's is in the code??? WHY?  
- No input sanitization.  
- Unhandled exception potential.
- Maybe learn how to secure your program?

</details>

<details>
<summary>Design</summary>

- This would be a lot better using different Python files for the code instead of installing 4 different executables for it?  
- A whole executable for deleting files?  
- Code is very hard to read.  
- Redundant code flooded throughout it.  
- Function naming is terribly inconsistent.  
- No data classes?

</details>

<details>
<summary>BUGSs</summary>

- Logic bugs such as `"[5] exit"` being under the choice 6.  
- Vague errors.  
- `download_file()` has a `raise` for status in the exception.  
- Silent failure logs?

</details>

<details>
<summary>Paths & File Handling</summary>

- Hardcoded paths, e.g., `C:\SS` for the folder.  
- Large files aren't handled well at all.  
- SRUM processing timestamp extraction assumes fixed filename format `\d{14}_...`.

</details>

<details>
<summary>Performance</summary>

- Lacks basic performance optimizations.  
- I/O operations — very inefficient.  
- Regex used way too much — bottlenecking.  
- Minimal logs.  
- Data structures are still dogshit.

</details>

<details>
<summary>Style</summary>

- Abuses `print` statements instead of adding simple logging features.  
- Error handling is terrible.  
- Unnecessary escape characters.  
- `blake3` import handling is awful.

</details>

---

🗑️ Honestly, Aweful code. does the job (poorly) but the coding behind this is utter dogshit
