| Step | Repositories |
|---|---:|
| Candidate list (Idowu et al.) | 31,066 |
| Scanned with the original entry-point rules | 31,066 |
| ├ clone failed (repository deleted / private) | 2,656 |
| ├ no Dockerfile and no root entry file | 18,161 |
| ├ Dockerfile found, no resolvable Python entry point | 4,306 |
| ├ entry point resolved | 5,943 |
| └ all six stages reachable (**original rules**) | **507** |
| Re-scanned with widened fallback rules (pass 2) | 22,467 |
| ├ entry point newly resolved | 2,192 |
| └ all six stages reachable (**widened rules**) | **179** |
| **Verified corpus (total)** | **686** |

Verified repositories by entry-point route:

- `fallback_root`: 398
- `fallback_nested`: 162
- `dockerfile?`: 82
- `fallback_console_script`: 39
- `dockerfile`: 5

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
