| Step | Repositories |
|---|---:|
| Candidate list (Idowu et al.) | 31,066 |
| **A. Scanned with the original entry-point rule** (Dockerfile, else root entry file) | 20,831 |
| ├ clone failed (repository deleted / private) | 1,757 |
| ├ no Dockerfile and no root entry file | 12,985 |
| ├ Dockerfile found, no resolvable Python entry point | 2,889 |
| ├ entry point resolved | 3,200 |
| └ all six stages reachable | **421** |
| **B. Scanned with the widened rule** (+ `src/`, `app/`, package, `console_scripts`) | 10,235 |
| ├ clone failed | 899 |
| ├ no entry point under any rule | 6,593 |
| ├ entry point resolved | 2,743 |
| └ all six stages reachable | **86** |
| **C. A's failures re-scanned with the widened rule** | 15,874 |
| ├ clone failed | 129 |
| ├ still no entry point | 13,553 |
| ├ entry point newly resolved | 2,192 |
| └ all six stages reachable | **179** |
| **Verified corpus (total)** | **686** |

Verified repositories by entry-point route:

- `fallback_root`: 455
- `fallback_nested`: 162
- `fallback_console_script`: 39
- `dockerfile`: 30

Stages reachable among repositories with a resolved entry point:

| stages | repos |
|---:|---:|
| 6 | 686 |
| 5 | 869 |
| 4 | 914 |
| 3 | 1,154 |
| 2 | 1,751 |
| 1 | 1,493 |
| 0 | 1,268 |
