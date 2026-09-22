# Inwentarz historii upstreamu

Zakres: d170961..14db58bad6e6ac2cb794b441c7b3d0d2a6dd1752, 319 commitów. Klasyfikacja automatyczna według zmienionych ścieżek (pierwsza pasująca kategoria), nie deklaracja przeglądu każdego diffu ani kompletnego przeniesienia commita. Merge liczony oddzielnie. Paczka dekodera pochodzi z odpowiadającej gałęzi upstream/v4 f7f82f7; zawiera adaptacje zgodności opisane w upstream-backports.md.

- Merge: 91
- Pozostały kod / zachowanie — oddzielna ocena: 111
- Dokumentacja / CI / przykłady: 36
- Dekoder CS2 (paczka; z adaptacjami): 58
- Zależności / migracje modułu (może obejmować kod): 17
- Generowane protokoły: 4
- Testy: 2

| Commit | Obszar | Opis |
|---|---|---|
| `14db58bad6` | Merge | Merge pull request #695 from youdie006/fix-silenced-nil-property |
| `7fb69d8704` | Pozostały kod / zachowanie — oddzielna ocena | fix: return false from Silenced() when m_bSilencerOn is missing |
| `d0324bd49b` | Dokumentacja / CI / przykłady | ci: disable csda step (#694) |
| `409f5b4e1b` | Dokumentacja / CI / przykłady | readme: revert all refs to v5 until v6 is fully released |
| `ddd002aa84` | Dokumentacja / CI / przykłady | readme: default to v5 for now |
| `a13e82bd33` | Dekoder CS2 (paczka; z adaptacjami) | perf: reduce parse hotspots (snappy dst reuse, field-path LUT, decoder boxing) (#691) |
| `0df72e7235` | Dokumentacja / CI / przykłady | ci: add least-privilege permissions to workflows (#690) |
| `7ea87c0c1e` | Merge | Merge pull request #689 from markus-wa/ci/osv-scanner |
| `fa3799e96f` | Dokumentacja / CI / przykłady | readme: replace dead Snyk badge with OSV-Scanner workflow badge |
| `166225c2a0` | Dokumentacja / CI / przykłady | ci: add OSV-Scanner dependency vulnerability scanning workflow |
| `67e1a33272` | Zależności / migracje modułu (może obejmować kod) | deps: upgrade golang.org/x/text+golang.org/x/image |
| `98ec6d54f4` | Dokumentacja / CI / przykłady | Remove Go Report badge |
| `86b539ce73` | Merge | Merge pull request #688 from markus-wa/fix/580-grenade-weapon-instance |
| `30fcf7901d` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): resolve nil Entity/Owner on grenade WeaponInstance (#580) |
| `40e84fa08c` | Merge | Merge pull request #686 from markus-wa/chore/v5-to-v6 |
| `c7d2ed3e4a` | Merge | Merge branch 'master' into chore/v5-to-v6 |
| `b793dd5b44` | Merge | Merge pull request #685 from markus-wa/perf/poly-decode-allocs |
| `f10d02b071` | Dekoder CS2 (paczka; z adaptacjami) | v5 -> v6 |
| `227d6f7b2b` | Dekoder CS2 (paczka; z adaptacjami) | perf: widen value caches and pool frame payload buffers |
| `cafef0f3b8` | Merge | Merge pull request #684 from markus-wa/docs/iswalking-318 |
| `c391983a39` | Pozostały kod / zachowanie — oddzielna ocena | docs(common): clarify IsWalking() reflects walk key, not movement |
| `b66e1d6460` | Dekoder CS2 (paczka; z adaptacjami) | perf(sendtablescs2): restore zero-alloc noscale decode, drop polyUpdate churn |
| `c1d131b3e3` | Merge | Merge pull request #658 from markus-wa/dependabot/go_modules/golang.org/x/image-0.41.0 |
| `3aac6cf62d` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump golang.org/x/image from 0.35.0 to 0.41.0 |
| `c8ed29f673` | Merge | Merge pull request #681 from markus-wa/chore/upgrade-go-1.27 |
| `b9e66f9412` | Merge | Merge pull request #663 from markus-wa/various-fixes |
| `3da8b437f7` | Merge | Merge origin/master into pr-663 |
| `7a893dd8e9` | Dekoder CS2 (paczka; z adaptacjami) | test: cover QAngle noscale decode, entity_killed, fatal-hit capping, sorted participants |
| `cc2ddf5697` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): guard BombDefuseStart.Site derivation on known bomb position |
| `422d96d3fe` | Merge | Merge pull request #654 from markus-wa/copilot/proper-support-for-polymorphic-fields |
| `755dd32f2a` | Dekoder CS2 (paczka; z adaptacjami) | docs: clarify maxPolyID memoization comment |
| `b929ecaffe` | Dekoder CS2 (paczka; z adaptacjami) | fix: robust poly bounds, loud desync detection, poly-aware PropertyEntries |
| `ae363df0e4` | Dekoder CS2 (paczka; z adaptacjami) | fix: dispatch update handlers in registration order across rebuilds and creation |
| `6e8f102e8e` | Pozostały kod / zachowanie — oddzielna ocena | test: add deathmatch regression for polymorphic game-mode rules |
| `f9d0e73d43` | Merge | Merge branch 'master' into copilot/proper-support-for-polymorphic-fields |
| `6d8e150312` | Dekoder CS2 (paczka; z adaptacjami) | fix: deterministic handler rebuild, harden poly refs, fix nested-table enumeration |
| `d127059109` | Merge | Merge remote-tracking branch 'origin/master' into pr-663 |
| `84ef0b42bc` | Merge | Merge pull request #683 from markus-wa/feat/knife-type |
| `1825985e30` | Dekoder CS2 (paczka; z adaptacjami) | fix: address polymorphic field review findings |
| `45dbe1af9d` | Dekoder CS2 (paczka; z adaptacjami) | fix: per-parser unique ids, review fixes and lint cleanup |
| `bf2c9b436e` | Pozostały kod / zachowanie — oddzielna ocena | feat: expose knife detail via original weapon string + KnifeType helper |
| `261396593a` | Pozostały kod / zachowanie — oddzielna ocena | chore(interfaces): regenerate GameState for map-accessor doc notes |
| `c9c698af92` | Pozostały kod / zachowanie — oddzielna ocena | feat(events): surface inflictor on OtherDeath and document its two producers |
| `2175e5a2a7` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): warn when guessing molotov from projectile class |
| `9285813f84` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): cap fatal HealthDamageTaken with reported health, exactly |
| `b8d55386e4` | Dokumentacja / CI / przykłady | docs(game-events): note CS:GO provenance and match-server ping absence |
| `6cfce92b14` | Pozostały kod / zachowanie — oddzielna ocena | docs(common): Player.Velocity() is zero on both GOTV flavours |
| `a17846f138` | Pozostały kod / zachowanie — oddzielna ocena | docs(common): document m_fireCount as spawned-count, not active-count |
| `8836bde37e` | Pozostały kod / zachowanie — oddzielna ocena | docs(state): note map accessors have non-deterministic iteration order |
| `79ab79ad98` | Pozostały kod / zachowanie — oddzielna ocena | fix(common): make Equipment.UniqueID2 deterministic |
| `65a13e443e` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): dispatch InfernoFireOut in deterministic entity-ID order |
| `c90c09f08a` | Pozostały kod / zachowanie — oddzielna ocena | chore(lint): silence gosec G115 on pawn-handle and entity-index casts |
| `73f759bac9` | Pozostały kod / zachowanie — oddzielna ocena | style(parser): drop redundant int conversion in FrameCount |
| `1785e02806` | Pozostały kod / zachowanie — oddzielna ocena | chore(interfaces): regenerate parser_interface for FrameCount doc |
| `a57ecb3e60` | Dokumentacja / CI / przykłady | docs(game-events): add defuser_dropped / defuser_pickup rows |
| `6248488bc5` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): dispatch unknown-equipment ParserWarn on the event dispatcher |
| `e2e547edaa` | Pozostały kod / zachowanie — oddzielna ocena | style: align entity_killed handler-map comment (gofmt) |
| `f53b28d058` | Dokumentacja / CI / przykłady | docs(game-events): note per-action cohort isn't tv_* controllable in GOTV |
| `5e86188f04` | Pozostały kod / zachowanie — oddzielna ocena | docs(events): note BulletDamage sub-tick data is recording-config gated |
| `0a3134bb5f` | Dokumentacja / CI / przykłady | docs(game-events): correct CS2 broadcast-GOTV availability columns |
| `3b977330f4` | Pozostały kod / zachowanie — oddzielna ocena | docs: clarify FlashDuration is the effective-blindness window |
| `9087ee0d85` | Pozostały kod / zachowanie — oddzielna ocena | docs(common): note AmmoReserve() era-dependent unit (magazines vs rounds) |
| `d948d9adc3` | Pozostały kod / zachowanie — oddzielna ocena | feat(parser): add FrameCount() returning -1 until the total is known |
| `b6ac932d5a` | Pozostały kod / zachowanie — oddzielna ocena | feat(events): add InfernoFireOut and correct InfernoExpired doc |
| `d8440def32` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): resolve grenade type by class and dispatch unknown-model warning |
| `8fc38dc365` | Dekoder CS2 (paczka; z adaptacjami) | fix(sendtables): decode 32-bit QAngle components as noscale floats |
| `c894827244` | Dekoder CS2 (paczka; z adaptacjami) | fix: size per-entity polySerializers by class reachability, not global count |
| `c1a87448fc` | Merge | Merge master into branch; resolve conflicts keeping poly support + master's name-resolution and fixes |
| `87a37a8407` | Pozostały kod / zachowanie — oddzielna ocena | fix: make collection accessors and grenade/inferno IDs deterministic |
| `4126b7b39a` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): pair PlayerFlashed victims by detonation, not FIFO order |
| `e1e45f5424` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): cap fatal-hit HealthDamageTaken at remaining HP |
| `f06cb5ace1` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): resolve PlayerHurt.Attacker via attacker_pawn fallback |
| `fc5f7ae43f` | Pozostały kod / zachowanie — oddzielna ocena | fix(events): dispatch OtherDeath for CS2 entity_killed |
| `c90332e441` | Pozostały kod / zachowanie — oddzielna ocena | feat(events): add typed VoteCast event |
| `58a161344a` | Pozostały kod / zachowanie — oddzielna ocena | feat(events): add Position to PlayerJump |
| `c168eef5e7` | Pozostały kod / zachowanie — oddzielna ocena | feat(events): add Site to BombDefuseStart |
| `aa49d39e44` | Pozostały kod / zachowanie — oddzielna ocena | fix(common): stop GrenadeProjectile.Velocity() panicking on CS2 demos |
| `b5c5f13a74` | Merge | Merge pull request #682 from markus-wa/fix/trailing-newline-reader-test |
| `db30954f22` | Merge | Merge branch 'master' into fix/trailing-newline-reader-test |
| `2d7b6e4c42` | Merge | Merge pull request #669 from WangChuDi/feat/full-usercmd-delta-upstream |
| `2bd78b25b3` | Dekoder CS2 (paczka; z adaptacjami) | fix: add missing trailing newline to reader_test.go |
| `381603a57e` | Zależności / migracje modułu (może obejmować kod) | require go 1.27 |
| `6ea13b1227` | Pozostały kod / zachowanie — oddzielna ocena | fix: appease upgraded golangci-lint in usercmd code |
| `9e96e54297` | Pozostały kod / zachowanie — oddzielna ocena | feat: default UserCmdParsingButtonsOnly instead of Full |
| `c595e5b566` | Pozostały kod / zachowanie — oddzielna ocena | fix: resolve usercmd player via controller entity, not userID |
| `4991758306` | Pozostały kod / zachowanie — oddzielna ocena | perf: add button-only usercmd parsing mode |
| `c7f87107a0` | Pozostały kod / zachowanie — oddzielna ocena | fix: fully decode delta-encoded user commands |
| `5756a2128a` | Pozostały kod / zachowanie — oddzielna ocena | fix: PlayerButtonsStateUpdate not working since last CS2 update |
| `a66db4bd56` | Merge | Merge pull request #680 from markus-wa/upgrade-linter |
| `ca955d2d4d` | Pozostały kod / zachowanie — oddzielna ocena | chore: add vscode conf |
| `a8d7b41b7c` | Dekoder CS2 (paczka; z adaptacjami) | ref: resolve linter warnings |
| `3b0a851984` | Dokumentacja / CI / przykłady | ci: install golangci-lint through official action |
| `4fcfce0534` | Dokumentacja / CI / przykłady | chore: upgrade linter config |
| `5025dc4a9a` | Merge | Merge pull request #679 from markus-wa/fix/bound-readbytes-allocation |
| `0d4e337b63` | Dekoder CS2 (paczka; z adaptacjami) | fix: bound readBytes allocation before decoding corrupt lengths |
| `23b661f94d` | Merge | Merge pull request #665 from Refrag/fix/bound-field-state-allocations |
| `4f190d599f` | Merge | Merge pull request #678 from markus-wa/fix/stop-message-processing-on-first-error |
| `426ea5e5c1` | Merge | Merge branch 'master' into fix/stop-message-processing-on-first-error |
| `f6d86d56dd` | Pozostały kod / zachowanie — oddzielna ocena | fix: skip all handler work once a fatal error is recorded |
| `d9f5e7a366` | Merge | Merge pull request #664 from Refrag/fix/abort-processing-after-error |
| `f64b088b7b` | Merge | Merge pull request #666 from markus-wa/dependabot/go_modules/google.golang.org/protobuf-1.36.12 |
| `e4fc98d229` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump google.golang.org/protobuf from 1.36.11 to 1.36.12 |
| `d9a0a13d50` | Merge | Merge pull request #670 from markus-wa/dependabot/go_modules/github.com/stretchr/testify-1.12.1 |
| `f336cb56c6` | Merge | Merge branch 'master' into dependabot/go_modules/github.com/stretchr/testify-1.12.1 |
| `4d3defaced` | Merge | Merge pull request #676 from markus-wa/fix/fma-contraction |
| `196b032ec1` | Merge | Merge branch 'master' into fix/fma-contraction |
| `a441e7821d` | Merge | Merge pull request #675 from markus-wa/fix-playerhurt-dispatch-timing |
| `3e941078c2` | Merge | Merge branch 'master' into fix-playerhurt-dispatch-timing |
| `ca6decbc1d` | Merge | Merge pull request #674 from markus-wa/fix-673-2 |
| `e03ac114bd` | Merge | Merge branch 'master' into fix-673-2 |
| `787182068c` | Merge | Merge pull request #677 from katsugtgz/ci/update-action-versions |
| `2e9b15485f` | Dokumentacja / CI / przykłady | ci: update actions/checkout to v7, setup-go to v7, cache to v6, codeql-action to v4, create-pull-request to v8 |
| `9891f6adca` | Merge | Merge pull request #667 from antonkesy/docs-fixes |
| `879779592b` | Dekoder CS2 (paczka; z adaptacjami) | fix: force intermediate rounding to prevent FMA contraction |
| `0d1bcc1f3a` | Pozostały kod / zachowanie — oddzielna ocena | fix: dispatch empty-weapon PlayerHurt before entity updates |
| `e7840700c2` | Pozostały kod / zachowanie — oddzielna ocena | feat: add player velocity |
| `50933536eb` | Dekoder CS2 (paczka; z adaptacjami) | fix: send node name collisions |
| `dafa8b3c60` | Merge | Merge branch 'master' into docs-fixes |
| `ed36111be5` | Merge | Merge pull request #672 from markus-wa/fix/quantized-float-rounding |
| `efd562b7f0` | Dekoder CS2 (paczka; z adaptacjami) | fix: round to nearest when quantizing floats |
| `23ffe61e90` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump github.com/stretchr/testify from 1.11.1 to 1.12.1 |
| `4a2c78b99b` | Dokumentacja / CI / przykłady | docs: fix typos |
| `7d71cbb82b` | Dekoder CS2 (paczka; z adaptacjami) | fix: bound field-state allocations to fail fast on corrupt bitstreams |
| `cd2a1169bc` | Pozostały kod / zachowanie — oddzielna ocena | fix: stop processing queued messages once a fatal error is recorded |
| `ed22bca069` | Merge | Merge pull request #660 from markus-wa/proto-up |
| `a1cfb4c413` | Pozostały kod / zachowanie — oddzielna ocena | feat: update proto messages |
| `16d295a045` | Merge | Merge pull request #659 from markus-wa/userid |
| `15cf1375ca` | Pozostały kod / zachowanie — oddzielna ocena | fix: always update player user ID in getOrCreatePlayer |
| `b2c3bf7c79` | Dekoder CS2 (paczka; z adaptacjami) | Fix remaining godox lint issues with nolint:godox on preceding lines |
| `fd00812987` | Dekoder CS2 (paczka; z adaptacjami) | Add nolint directives for gocognit and nestif linting issues |
| `7837f8ee0a` | Dekoder CS2 (paczka; z adaptacjami) | Add nolint directives for gocognit and nestif linting issues |
| `0ff51a83e7` | Dekoder CS2 (paczka; z adaptacjami) | Fix index-out-of-range panic: assign polySerializerId before calling setModel |
| `dfedf3866a` | Merge | Merge master into branch; resolve conflicts in field.go and entity.go |
| `b375824720` | Merge | Merge pull request #655 from markus-wa/mw/bcast-fix-user-id-mappings |
| `44984e75f4` | Pozostały kod / zachowanie — oddzielna ocena | broadcasts: fix player user-id mappings when starting parsing mid-match |
| `b4de502918` | Pozostały kod / zachowanie — oddzielna ocena | pool bit reader where appropriate |
| `5fe42999e4` | Dekoder CS2 (paczka; z adaptacjami) | interface{} -> any |
| `6283ef5bd9` | Pozostały kod / zachowanie — oddzielna ocena | remove unused source1 func |
| `ce1396a8ea` | Dekoder CS2 (paczka; z adaptacjami) | Clarify polyTypes comment: index 0 is the field's own serializer not just 'base' |
| `6471569cec` | Dekoder CS2 (paczka; z adaptacjami) | Implement per-entity polymorphic pointer state tracking |
| `5178aa2499` | Dokumentacja / CI / przykłady | readme: fix Esportal blurb |
| `096e611841` | Dekoder CS2 (paczka; z adaptacjami) | Fix polyTypes to include base serializer at index 0, matching Clarity exactly |
| `3ec5b524c1` | Dekoder CS2 (paczka; z adaptacjami) | Fix polymorphic field handling: 0-based indexing, conditional ubitvar, model determination |
| `5cb1b7e9aa` | Pozostały kod / zachowanie — oddzielna ocena | Initial plan |
| `b1bc851d03` | Merge | Merge pull request #644 from markus-wa/mw/perf2026 |
| `18ad4c2807` | Dekoder CS2 (paczka; z adaptacjami) | fix: resolve CI lint issues (gci, gofumpt, staticcheck ST1006) |
| `22bbb00644` | Dekoder CS2 (paczka; z adaptacjami) | refactor: remove dead code instead of using nolint:unused |
| `1bae9a557b` | Dekoder CS2 (paczka; z adaptacjami) | chore: add nolint directives for pre-existing lint issues and perf-related complexity |
| `87da39a5e4` | Dekoder CS2 (paczka; z adaptacjami) | perf(cs2): improve f32Cache hash to reduce collisions for clustered floats |
| `24aae799d3` | Dekoder CS2 (paczka; z adaptacjami) | perf(cs2): fix collection fieldState resize to use pointer + exponential growth |
| `5bffa7e2ca` | Dekoder CS2 (paczka; z adaptacjami) | perf(cs2): reduce GC pressure with decoder value caches |
| `1d8d0dfccf` | Dekoder CS2 (paczka; z adaptacjami) | perf: eliminate string map lookups for handler dispatch, single-pass field decoder |
| `ab91f2950c` | Dekoder CS2 (paczka; z adaptacjami) | perf: add O(1) flat cache for field path names, tune fieldState capacity, improve readBoolean |
| `4b920b3e3b` | Dekoder CS2 (paczka; z adaptacjami) | perf: flat huffman tree, reader pool, inlineable nextByte, set fast path |
| `7d59443f85` | Dekoder CS2 (paczka; z adaptacjami) | perf: reduce CPU and allocation overhead in CS2 entity parsing |
| `395ec0b6e1` | Merge | Merge pull request #651 from markus-wa/copilot/fix-infinite-recursion-getthrowngrenade |
| `b1ebbb3899` | Pozostały kod / zachowanie — oddzielna ocena | Fix getThrownGrenade infinite recursion on circular ControlledBot references (#620) |
| `67a2bdfe64` | Merge | Merge pull request #653 from Refrag/fix-cglobalsymbol-decoder |
| `696210ba10` | Dekoder CS2 (paczka; z adaptacjami) | fix: decode CGlobalSymbol as null-terminated string |
| `ac4ac6277e` | Merge | Merge pull request #648 from WangChuDi/fix/issue-642-playerhurt-world-damage |
| `2f189c628a` | Pozostały kod / zachowanie — oddzielna ocena | fix bomb damage logic |
| `2fa735f886` | Pozostały kod / zachowanie — oddzielna ocena | Clarify still-in-progress round-end fallback |
| `69c737a8c2` | Pozostały kod / zachowanie — oddzielna ocena | nolint:exhaustive |
| `4e3ab64a45` | Pozostały kod / zachowanie — oddzielna ocena | Remove stale attackerWeaponType assertion |
| `d0e268c965` | Pozostały kod / zachowanie — oddzielna ocena | Polish empty-weapon PlayerHurt follow-ups |
| `0f64f8a381` | Pozostały kod / zachowanie — oddzielna ocena | Reduce empty-weapon PlayerHurt fix scope |
| `35eb92a5d0` | Pozostały kod / zachowanie — oddzielna ocena | Mirror bomb explode frame tracking in datatables |
| `4c1a493624` | Pozostały kod / zachowanie — oddzielna ocena | Fix empty-weapon PlayerHurt classification |
| `df480af991` | Merge | Merge pull request #647 from WangChuDi/fix/cs2-position-eyes |
| `c62646531c` | Merge | Merge branch 'master' into fix/cs2-position-eyes |
| `3c00706610` | Pozostały kod / zachowanie — oddzielna ocena | Reuse resolved pawn entity for eye-position offset |
| `a218992429` | Pozostały kod / zachowanie — oddzielna ocena | Move eye-position offset lookup onto Player |
| `73ce35d33d` | Pozostały kod / zachowanie — oddzielna ocena | Add optional float property helper tests |
| `61eb99dc7b` | Pozostały kod / zachowanie — oddzielna ocena | Return eye-position availability from PositionEyes |
| `bbf041282c` | Pozostały kod / zachowanie — oddzielna ocena | Add eye-position availability helper |
| `850d065e0d` | Pozostały kod / zachowanie — oddzielna ocena | Harden player eye-position fallback |
| `e254bc2054` | Pozostały kod / zachowanie — oddzielna ocena | Add player eye-position helper for CS2 pawns |
| `dbe2114f8a` | Merge | Merge pull request #646 from markus-wa/anim2 |
| `950dc16923` | Dekoder CS2 (paczka; z adaptacjami) | fix: support for animgraph 2 demos |
| `a8c51bdd40` | Merge | Merge pull request #640 from NeptuneMagicSauce/ninja_defuse |
| `3d0d69c15c` | Dokumentacja / CI / przykłady | ninja defuse analyzer: fix unit test integration |
| `d72c5da4aa` | Merge | Merge branch 'master' into ninja_defuse |
| `2f20019bdb` | Merge | Merge pull request #643 from markus-wa/dependabot/go_modules/golang.org/x/image-0.36.0 |
| `baadcdbb1e` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump golang.org/x/image from 0.18.0 to 0.36.0 |
| `674f8dafa3` | Merge | Merge pull request #624 from markus-wa/dependabot/go_modules/github.com/oklog/ulid/v2-2.1.1 |
| `ebbff0a7b1` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump github.com/oklog/ulid/v2 from 2.1.0 to 2.1.1 |
| `51be2f96f2` | Merge | Merge pull request #625 from markus-wa/dependabot/go_modules/google.golang.org/protobuf-1.36.11 |
| `f111a04c07` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump google.golang.org/protobuf from 1.36.4 to 1.36.11 |
| `5af49686ff` | Merge | Merge pull request #626 from markus-wa/dependabot/go_modules/github.com/stretchr/testify-1.11.1 |
| `8171f2c5d2` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump github.com/stretchr/testify from 1.10.0 to 1.11.1 |
| `2d89bd7e78` | Merge | Merge branch 'master' into ninja_defuse |
| `4cad6fdb25` | Zależności / migracje modułu (może obejmować kod) | revert back to github.com/llgcode/draw2d (couldnt fix deps) |
| `ef9cafdac0` | Zależności / migracje modułu (może obejmować kod) | deps: go back to go1.24 as min version (downgrade tdewolff/canvas) |
| `4b3c3118af` | Dokumentacja / CI / przykłady | examples/nade-trajectories: add origin & target indicators |
| `cb3df9489a` | Zależności / migracje modułu (może obejmować kod) | deps: github.com/llgcode/draw2d/draw2dimg -> github.com/tdewolff/canvas |
| `d090e19512` | Pozostały kod / zachowanie — oddzielna ocena | cstv broadcasts: fix parsing failing / skipping first delta frame |
| `9193d7c18e` | Dokumentacja / CI / przykłady | ninja defuse analyzer: fix linter errors |
| `f93f7e5967` | Dokumentacja / CI / przykłady | ninja defuse analyzer |
| `f746e6e57e` | Generowane protokoły | protobuf update |
| `cd4d8e6234` | Merge | Merge pull request #639 from csskill/patch-1 |
| `5b53f8827e` | Dokumentacja / CI / przykłady | Add csskill.com to project list in README |
| `d4defdd266` | Merge | Merge pull request #637 from cooltg66/patch-1 |
| `015248f205` | Merge | Merge branch 'master' into patch-1 |
| `63e843c85d` | Merge | Merge pull request #638 from mhdiiilham/fix/nil-pointer-bind-bomb |
| `5466e2e806` | Pozostały kod / zachowanie — oddzielna ocena | fix: prevent nil pointer dereference in bindBomb when parsing certain demos |
| `44866fc794` | Dokumentacja / CI / przykłady | Update description for clutchkings.gg |
| `6142562509` | Dokumentacja / CI / przykłady | Add clutchkings.gg to services using demoinfocs-golang |
| `b3b670d27c` | Dokumentacja / CI / przykłady | Happy 2026 |
| `96c0d7cfe3` | Merge | Merge pull request #631 from markus-wa/up-proto |
| `36ec797a16` | Merge | Merge pull request #633 from markus-wa/fix-decoder |
| `c3da22c7aa` | Dekoder CS2 (paczka; z adaptacjami) | fix: wrong ResourceId_t decoder leading to huge mem allocation |
| `9022661243` | Pozostały kod / zachowanie — oddzielna ocena | feat: update proto msgs |
| `0dc7bdc1db` | Merge | Merge pull request #630 from markus-wa/fix-spotted |
| `d34a52d9ce` | Pozostały kod / zachowanie — oddzielna ocena | fix: panic when calling player#IsSpottedBy |
| `b51baf51eb` | Pozostały kod / zachowanie — oddzielna ocena | fix debugdemoinfocs |
| `94f94598b4` | Merge | Merge pull request #628 from markus-wa/rm-inspect |
| `caf0efe92b` | Pozostały kod / zachowanie — oddzielna ocena | remove player#InspectWeaponCount |
| `6294141aec` | Dekoder CS2 (paczka; z adaptacjami) | remove dead code |
| `2a6a67f2a3` | Pozostały kod / zachowanie — oddzielna ocena | add note about BulletDamage possibly not being available |
| `e6c25a93fc` | Merge | Merge pull request #627 from markus-wa/buttons |
| `c055c69ebc` | Dekoder CS2 (paczka; z adaptacjami) | feat: add fields/functions to get player buttons related info |
| `28d2d5ed6d` | Merge | Merge pull request #582 from markus-wa/dependabot/go_modules/github.com/golang/snappy-1.0.0 |
| `9a42edf0fd` | Dekoder CS2 (paczka; z adaptacjami) | fix typo (#615) |
| `f615c263b9` | Merge | Merge pull request #619 from markus-wa/fix-equip |
| `dd2e92a3a1` | Merge | Merge pull request #623 from billfreeman44/csc-reference |
| `a0cce8e402` | Dokumentacja / CI / przykłady | Add CSC link to CS2 resources in README |
| `fd2b317495` | Merge | Merge pull request #622 from maxpain/patch-1 |
| `fbe053fae0` | Dokumentacja / CI / przykłady | Add fastcup.net to services using demoinfocs-golang |
| `c8786da4b9` | Pozostały kod / zachowanie — oddzielna ocena | fix: possible panic in player.EquipmentValueCurrent() |
| `305b5c16c5` | Merge | Merge pull request #617 from RiotNOR/master |
| `929dfb0e38` | Pozostały kod / zachowanie — oddzielna ocena | Make sure only actual flashbangs are added to flyingFlashbangs. |
| `b735de4119` | Merge | Merge pull request #612 from markus-wa/event-fallback-update |
| `e4a42d0e04` | Merge | Merge branch 'master' into event-fallback-update |
| `4e498958e6` | Pozostały kod / zachowanie — oddzielna ocena | fix nil deref on Player.PlayerPawnEntity() part 2 |
| `ab871b09b6` | Pozostały kod / zachowanie — oddzielna ocena | fix nil deref on Player.PlayerPawnEntity() |
| `2af5a1a831` | Dokumentacja / CI / przykłady | readme: |
| `5f97ebdd9f` | Pozostały kod / zachowanie — oddzielna ocena | feat: event list fallback to support 15/10/2025 update |
| `575c95f30f` | Merge | Merge pull request #611 from markus-wa/mw/update-protobuufs-15th-oct-25 |
| `bea69de4f4` | Dekoder CS2 (paczka; z adaptacjami) | add VectorWS decoder |
| `3ea42aa8d1` | Pozostały kod / zachowanie — oddzielna ocena | clean up weapon prop formatting |
| `ad5a889b94` | Pozostały kod / zachowanie — oddzielna ocena | update protobufs |
| `20f9184634` | Pozostały kod / zachowanie — oddzielna ocena | broadcast arsing: implement token_redirect |
| `994ece7c00` | Dokumentacja / CI / przykłady | LD_LIBRARY_PATH note |
| `45967f8047` | Dokumentacja / CI / przykłady | fix broadcast example |
| `81d8b46de5` | Merge | Merge pull request #607 from markus-wa/stop-cmd |
| `358a6e958a` | Pozostały kod / zachowanie — oddzielna ocena | fix: stop parsing on EDemoCommands_DEM_Stop |
| `7be07fd285` | Merge | Merge pull request #605 from markus-wa/fix-disconnect-players |
| `204351a493` | Merge | Merge pull request #606 from markus-wa/player-chat |
| `9358bad218` | Pozostały kod / zachowanie — oddzielna ocena | ref: add player_chat event as known events |
| `a31cefb134` | Pozostały kod / zachowanie — oddzielna ocena | fix: delete disconnected players references |
| `b1909f883a` | Merge | Merge pull request #602 from markus-wa/mw/update-protos-28.07.25 |
| `6852d153f0` | Merge | Merge remote-tracking branch 'origin/master' into mw/update-protos-28.07.25 |
| `6a7b303030` | Pozostały kod / zachowanie — oddzielna ocena | fix: bidirectional messages creator fallback for net messages |
| `f8ab98291f` | Dekoder CS2 (paczka; z adaptacjami) | update protos |
| `e53286d9d3` | Merge | Merge pull request #603 from markus-wa/flash |
| `6fd4f47d25` | Pozostały kod / zachowanie — oddzielna ocena | feat: add player.FlashbangCount() |
| `020999b978` | Pozostały kod / zachowanie — oddzielna ocena | fix: event list fallback to support 29/07/2025 update |
| `e330aad920` | Testy | fix test |
| `0c5cd95118` | Testy | fix compilation error 2.0 |
| `da6c37c592` | Dekoder CS2 (paczka; z adaptacjami) | fix compilation error |
| `236b3b52ca` | Pozostały kod / zachowanie — oddzielna ocena | fire missing round announce match start game event |
| `2b9a0025b7` | Dekoder CS2 (paczka; z adaptacjami) | remove dead code |
| `7076960ac4` | Dekoder CS2 (paczka; z adaptacjami) | clean up more csgo stuff + ParseBroadcast funcs |
| `4ed45f2d2e` | Pozostały kod / zachowanie — oddzielna ocena | v5ify |
| `a54dff2010` | Dokumentacja / CI / przykłady | readme: deprecate v4 |
| `18435ee803` | Generowane protokoły | update protos |
| `ff069e759a` | Merge | Merge remote-tracking branch 'origin/master' into v5 |
| `454fddaf76` | Merge | Merge pull request #592 from captainswain/feat/viewmodel_offsets |
| `0722cfc73f` | Merge | Merge pull request #600 from markus-wa/nil-fields |
| `579b959a20` | Pozostały kod / zachowanie — oddzielna ocena | feat: ignore #CSGO_No_Longer_Coach text messages |
| `d440edcf71` | Pozostały kod / zachowanie — oddzielna ocena | fix: possible nil players/weapons fields in some events |
| `f5f80e7a1e` | Merge | Merge pull request #599 from markus-wa/smoke-uniqueid |
| `9c2b44a826` | Pozostały kod / zachowanie — oddzielna ocena | fix: possible nil Weapon field in player hurt events |
| `83c839ad1a` | Pozostały kod / zachowanie — oddzielna ocena | fix: SmokeStart wrong UniqueID2() |
| `d4feac50d5` | Merge | Merge pull request #598 from markus-wa/update-proto |
| `704a6159e6` | Pozostały kod / zachowanie — oddzielna ocena | fix: update proto defs |
| `097b925a37` | Pozostały kod / zachowanie — oddzielna ocena | fix SmokeStart wrong UniqueID2() - #596 |
| `d2bceb7a94` | Dokumentacja / CI / przykłady | link v5 example |
| `0fd53f500c` | Dokumentacja / CI / przykłady | update go get |
| `20e6497b69` | Pozostały kod / zachowanie — oddzielna ocena | Add ViewmodelOffset() and ViewmodelFOV() to player, add example. |
| `51553807a2` | Zależności / migracje modułu (może obejmować kod) | require go 1.24 |
| `6a6eb0899a` | Dekoder CS2 (paczka; z adaptacjami) | fix random ordered create handlers |
| `fdd9c7c78b` | Dokumentacja / CI / przykłady | golangci-lint upgrade |
| `0ce66de808` | Pozostały kod / zachowanie — oddzielna ocena | update default.golden |
| `dd0cfd60e5` | Pozostały kod / zachowanie — oddzielna ocena | add broadcast example |
| `87c1934679` | Pozostały kod / zachowanie — oddzielna ocena | no longer export DemoHeader etc. - should use DemoFileHeader & ServerInfo |
| `8cd2bcb89e` | Generowane protokoły | update protobufs |
| `f1f875f7a8` | Merge | Merge remote-tracking branch 'origin/master' into v5 |
| `f9e77b19f0` | Zależności / migracje modułu (może obejmować kod) | chore(deps): bump github.com/golang/snappy from 0.0.4 to 1.0.0 |
| `9353ed2572` | Dekoder CS2 (paczka; z adaptacjami) | remove dead code (v5 api cleanup) |
| `081311736a` | Dokumentacja / CI / przykłady | v5 needs go 1.23 |
| `984dfafbd4` | Dokumentacja / CI / przykłady | readme make example nicer to read |
| `af4be3df4f` | Pozostały kod / zachowanie — oddzielna ocena | add Parse() & ParseFile() utility funcs |
| `b43555e1a3` | Merge | Merge branch 'deps-upgrades' into v5 |
| `1913ee7dde` | Zależności / migracje modułu (może obejmować kod) | go mod tidy |
| `ef56e2c7de` | Merge | Merge branch 'master' into v5 |
| `a53f1fb753` | Pozostały kod / zachowanie — oddzielna ocena | remove dead code |
| `6551a1599c` | Pozostały kod / zachowanie — oddzielna ocena | expose Player.ActiveWeaponID() |
| `c82700c08b` | Pozostały kod / zachowanie — oddzielna ocena | rename GrenadeProjectile.Trajectory2 -> Trajectory + add tick |
| `d78f2af685` | Pozostały kod / zachowanie — oddzielna ocena | header: remove unused protocol + signon length |
| `279f3d049a` | Merge | Merge branch 'mw/remove-csgo' into v5 |
| `2709ef726d` | Dekoder CS2 (paczka; z adaptacjami) | prep for merge with v5 |
| `3cd119559f` | Generowane protokoły | fix protobuf generator |
| `35b22b95bc` | Pozostały kod / zachowanie — oddzielna ocena | fix more tests post csgo cleanup |
| `282c3a93ae` | Dekoder CS2 (paczka; z adaptacjami) | removed more csgo code, fixed tests |
| `5eda81240c` | Pozostały kod / zachowanie — oddzielna ocena | remove unused encryption support |
| `2422bb3117` | Zależności / migracje modułu (może obejmować kod) | fix examples |
| `90a93a5234` | Dekoder CS2 (paczka; z adaptacjami) | wip: remove csgo support |
| `71bf29a001` | Dokumentacja / CI / przykłady | ci: use go.1.21 |
| `61bc4da358` | Dekoder CS2 (paczka; z adaptacjami) | perf: reduce memory usage + increase speed ~10% |
| `b3efefee4c` | Merge | Merge remote-tracking branch 'origin/master' into cstv-broadcast-parsing |
| `e8fb682c9a` | Merge | Merge remote-tracking branch 'origin/v5' into cstv-broadcast-parsing |
| `81f8a85454` | Merge | Merge remote-tracking branch 'origin/master' into cstv-broadcast-parsing |
| `7bbcd7a177` | Pozostały kod / zachowanie — oddzielna ocena | cstv: handle EOF & close response bodies |
| `addb80ed63` | Zależności / migracje modułu (może obejmować kod) | cstv broadcast parsing |
| `24b77fe5eb` | Pozostały kod / zachowanie — oddzielna ocena | use go 1.22 slices.Sort for more efficient, no-alloc sorting |
| `2a8182bdd7` | Dekoder CS2 (paczka; z adaptacjami) | avoid some allocs to reduce GC overhead |
| `ad06761dae` | Pozostały kod / zachowanie — oddzielna ocena | remove deprecated Player.Velocity() & Player.PreviousFramePosition due to performance concerns |
| `df0da134ab` | Dekoder CS2 (paczka; z adaptacjami) | v4 -> v5 |
