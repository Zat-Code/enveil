# Enveil - Architecture

## Stack
- **Langage**: Rust
- **CLI Framework**: Clap
- **Tools**: Git hooks, regex
- **Testing**: Unit tests + integration tests

## Structure

```
enveil/
├── src/
│   ├── main.rs           # Entry point
│   ├── lib.rs            # Library
│   ├── commands/         # CLI commands
│   │   ├── scan.rs      # Scan for exposed secrets
│   │   ├── protect.rs   # Add git hooks
│   │   └── check.rs     # Check current state
│   ├── detector/         # Secret detection
│   │   └── mod.rs
│   └── utils/
│       └── mod.rs
├── hooks/                # Git hooks templates
├── tests/
├── Cargo.toml
├── README.md
└── .env.example
```

## Features

1. Scan de fichiers - Détecte les secrets
2. Masquage interactif - Preview et remplace
3. Vault sécurisé - Stockage chiffré (age)
4. Git hooks - Pre-commit, pre-push
5. CI protection - GitHub Action
6. Templates .env - Génère .env.example
7. Alertes - Mode watch
8. Audit log - Historique
9. CI/CD intégration
10. Multi-format

## Plan

1. [ ] Setup projet Rust + Clap
2. [ ] Command scan basique
3. [ ] Detector de secrets
4. [ ] Command protect
5. [ ] Git hooks
6. [ ] Tests
7. [ ] Release v0.1.0
