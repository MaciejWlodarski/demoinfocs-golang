**Zbiorczy backport dekodera upstreamu (2026-09-22)**

Bazą pozostaje fork `d170961168e981a53e99e55e9722d4e56def2f0b` i jego publiczne API `/v4`. Konsument `demo-parser-cs2` nadal wskazuje `bdfe88762418`; tego przypięcia nie zmieniono. Dalsze prace nad Velocity są poza zakresem tego etapu.

Pierwsze fragmenty (następnie rozszerzone o paczkę dekodera poniżej):

| Zmiana | Źródło upstream | Zakres |
|---|---|---|
| `Equipment.Silenced()` zwraca false, gdy klasa nie ma `m_bSilencerOn` | [7fb69d8](https://github.com/markus-wa/demoinfocs-golang/commit/7fb69d8), włączone w 14db58b | Ochrona przed nil dereference; dotychczasowe on/off bez zmian |
| Cache wartości uint64 od 0 do 1023 w `unsignedDecoder` | [a13e82b](https://github.com/markus-wa/demoinfocs-golang/commit/a13e82b) | Tylko ponowne użycie wartości opakowanych w interface; bez pozostałych zmian tego commita |

Cache jest inicjalizowany raz i później tylko odczytywany. Wartości poza zakresem nadal przechodzą dotychczasową ścieżką. Typ wyniku pozostaje uint64. Testy obejmują granice cache, MaxUint32, czytanie wyrównane i niewyrównane do bajtu oraz pozycję odczytu po zdekodowaniu wartości.

**Punkt odniesienia bibliotek i aplikacji**

`pkg/demoinfocs/testdata/gotv/demo{1,2}.json` powstały na czystym d170961 w oddzielnej kopii, przed użyciem ich do oceny backportów. Nie zostały wygenerowane z nowej implementacji. Zawierają:

- SHA-256 pliku demo, mapę, protokół, HLTV, wynik, klatki i końcowy tick;
- liczniki wszystkich emitowanych typów eventów, z opisanym niżej wyjątkiem bootstrapu;
- hashe ticków i wybranych pól killi, obrażeń, strzałów, rzutów i końców rund;
- hashe danych 17 własnych typów eventów używanych przez konsumenta;
- próbki pozycji, historii pozycji, kąta, flag, HP, armora, alive/coaching, ekwipunku i aktywnej broni oraz listy żywych graczy, co co najmniej 64 ticki.

W niezależnych aktualizacjach w jednej klatce kolejność może zależeć od iteracji map Go. Dlatego w obrębie klatki sortowane są rekordy jednego rodzaju; zachowane są wszystkie ticki, wartości i liczba powtórzeń. Test nie gwarantuje identycznej kolejności callbacków wewnątrz tej samej klatki. Nie obejmuje każdego pola publicznego API.

Przy czterech przebiegach niezmienionego forka na Anubisie wystąpiło naprzemiennie 170 albo 171 PlayerSpawn. Jedyną różnicą był dodatkowy spawn w ticku 0, klatce 31. Z tego powodu PlayerSpawn w ticku 0 są raportowane przez test osobno i nie wchodzą do porównania golden. Wszystkie spawny po ticku 0 podlegają ścisłemu porównaniu. Nie zmieniano zachowania produkcyjnego spawnu.

`consumer.json` przechowuje oddzielne hashe JSON aplikacji dla przypiętego bdfe887 oraz lokalnego d170961, a także odcisk źródeł konsumenta, danych dem i pliku mapy. Źródła konsumenta obejmują zastaną lokalną zmianę `match/player_state.go`; oryginalny projekt nie został zmodyfikowany.

Skrypt `scripts/check-consumer-compatibility.py` buduje tymczasową kopię konsumenta z aktualnym forkiem i porównuje wynik z d170961. Normalizuje wyłącznie kolejność kluczy JSON, inventory oraz seen_events według ticka i zawartości. Nie usuwa żadnych pól wynikowych, nie pomija różnic liczbowych i nie aktualizuje automatycznie wzorca. Hash pinned służy do udokumentowania odrębnej wersji aplikacji; nie jest mylony z oczekiwanym wynikiem bieżącej biblioteki.

**Uruchomienie testów**

Wymagane lokalne pliki, bez automatycznego pobierania i bez dodawania dem do Gita:

| Nazwa w katalogu testowym | Oryginalny plik | Mapa |
|---|---|---|
| demo1.dem | 1-b5a573c6-ebba-4daa-b017-abb308d2077a-1-1.dem.zst | Mirage |
| demo2.dem | 1-b5a573c6-ebba-4daa-b017-abb308d2077a-2-1.dem.zst | Anubis |

Po rozpakowaniu przez zstd:

```sh
go test -tags unassert_panic -short ./...
go test -race -tags unassert_panic -short ./...
DEMOINFOCS_GOTV_DIR=/path/to/demos go test -tags unassert_panic ./pkg/demoinfocs -run '^TestGOTVCompatibility$' -count=2
```

Bez `DEMOINFOCS_GOTV_DIR` test GOTV jest pomijany. Gdy katalog wskazano jawnie, brak pliku lub błędny SHA-256 kończy test błędem. `-short` zawsze pomija pełne parsowanie dem. Wymuszone tworzenie nowych golden wymaga `DEMOINFOCS_UPDATE_GOTV=1`; należy to robić wyłącznie na jawnie wybranym punkcie odniesienia, nigdy w celu usunięcia niewyjaśnionej różnicy kandydata.

Pełna aplikacja (Python 3.11+, Go, lokalny konsument i jego mapy):

```sh
python3 scripts/check-consumer-compatibility.py \
  --consumer /path/to/demo-parser-cs2 \
  --demos /path/to/demos \
  --maps /path/to/demo-parser-cs2/maps \
  --output /tmp/consumer-check-new-directory
```

Skrypt wymaga nowego katalogu wynikowego, zachowuje tam logi i rzeczywiste JSON-y. Buduje kopię źródeł, więc nie modyfikuje go.mod/go.sum konsumenta. Przy innym stanie źródeł, zestawie map lub demach odmawia porównywania z niepasującym wzorcem. W badanym zestawie dostępny jest kdtree Mirage; dla Anubis nie ma kdtree. Test nie obejmuje eksportu replay ani trybu live/SSE.

W środowisku ograniczającym zapis do standardowego cache Go można dodać `GOCACHE=/tmp/demoinfocs-go-cache` przed poleceniami.

Mikrobenchmark dekodera:

```sh
go test ./pkg/demoinfocs/sendtables2 -run '^$' -bench '^BenchmarkUnsignedDecoder$' -benchmem -count=3
```

Na Go 1.27.1 / Apple M5 odczyt 512 zmienił się z 8 B i jednej alokacji na wywołanie na 0 B / 0 alokacji. Mediana trzech przebiegów: 8,652 ns → 4,775 ns. Dla 65536 pozostaje 8 B / jedna alokacja (mediany 10,49 ns → 10,75 ns). To mikrobenchmark pojedynczego dekodera, nie pomiar przyspieszenia całej aplikacji. Pierwszy pomiar bazowy 512 miał większy rozrzut; nie należy nadinterpretować małych różnic czasowych.

**Weryfikacja etapu**

- Krótkie testy wszystkich pakietów: PASS.
- Krótkie testy z race detector: PASS.
- Pełne porównanie obu dem z golden, dwa przebiegi: PASS.
- Kompilacja konsumenta i pełne JSON-y obu dem względem d170961: PASS po opisanej normalizacji kolejności.
- Publiczne API forka, ustawienia aplikacji i Velocity zachowano. Zależności runtime bez aktualizacji wersji; testify jest teraz zależnością bezpośrednią testów, wraz z jego zależnościami pośrednimi.

**Zbiorcza aktualizacja dekodera**

Przeniesiono cały pakiet `sendtables2` z `upstream/v4` (`f7f82f7`), następnie dostosowano go do zachowania forka. Gałąź v4 pozwala korzystać z backportów upstreamu bez migracji modułu i własnego API do v6. W zakresie `d170961..upstream/v4` 34 commity dotykają tego pakietu; przeniesiono jego wynikowy stan z opisanymi wyjątkami, nie wszystkie zmiany tych commitów. To aktualizacja stanu kodu, nie seria cherry-picków ani pełny merge. Inwentarz wszystkich 319 commitów zakresu `d170961..14db58b` znajduje się w [upstream-commit-inventory.md](upstream-commit-inventory.md). 91 pozycji to merge’e; 58 dotyka dekodera CS2, ale część zawiera też zmiany poza nim. Klasyfikacja ścieżek nie oznacza ręcznego przeglądu każdego commita ani przeniesienia wszystkich jego zmian.

Paczka obejmuje szybszy odczyt bitów, tablicę wyszukiwania Huffmana, cache ścieżek i callbacków po identyfikatorach, cache wartości uint/float, pooling readerów, wspólny przebieg wyboru dekodera, obsługę polimorficznych serializerów per encja, unieważnianie cache po zmianie typu, poprawki QAngle/quantizedfloat i testy upstreamu. Testy polimorfizmu obejmują niezależność encji, przełączanie typu, kolejność callbacków, zagnieżdżenia i błędne referencje.

Adaptacje wymagane dla forka:

- Zachowano `Parser.Entities()` oraz niszczenie aktywnej starej encji przy zastąpieniu jej nową.
- Zachowano dotychczasowe nazwy właściwości i pozycji. Kwalifikacja przez send-node z upstreamu powodowała nil dereference w istniejących callbackach gracza. W tej paczce nie jest aktywna.
- Wektory nadal mają typ `[]float32`, z niezależnym backing array dla każdego wyniku. Upstreamowe `[3]float32` łamało `PropertyValue.R3Vec()`; cache współdzielący mutowalne slice’y byłby zmianą semantyki. Test obejmuje typ i niezależność kolejnych wyników.
- Zachowano zachowanie snapshotów kolekcji z forka. In-place resize upstreamu usuwał bazowe atrybuty skinów przy późniejszych aktualizacjach długości. Test całej aplikacji wykazał 11814 różnic pól na Mirage i 4185 na Anubisie, wyłącznie paint_id/pattern/float. Po adaptacji całe JSON-y wróciły do wzorca bez aktualizowania golden.
- Początkowe callbacki są teraz wykonywane w kolejności rejestracji, zgodnie z upstreamem. Testy dem normalizują kolejność niezależnych zdarzeń wewnątrz jednej klatki; nie gwarantują zachowania dawnej losowej kolejności map Go.

Nie przeniesiono hurtowo warstwy zdarzeń upstreamu, migracji /v6, generowanych protokołów ani pozostałego kodu aplikacyjnego. To pozostaje oddzielnym zakresem; własne eventy i logika forka mają pierwszeństwo. Dwa dema stanowią sprawdzony korpus GOTV, nie gwarancję zgodności wszystkich formatów. Polimorfizm sprawdzono testami syntetycznymi, ponieważ nie ma osobnego demo deathmatch w tym korpusie.

**Weryfikacja paczki zbiorczej**

- `go test -race -tags unassert_panic -short ./...`: PASS, w tym przejęte testy polimorfizmu/QAngle i test zgodności mutowalnych wektorów.
- GOTV golden dla obu dem, `-count=2`: PASS.
- Pełny konsument: Mirage i Anubis PASS; hashe wyników identyczne z lokalnym d170961 po udokumentowanej normalizacji kolejności. Nie zmieniono wzorców.
- `git diff --check`: PASS.
- Zmiany są lokalne na `work/upstream-backports-stage1`; zależność w rzeczywistym `demo-parser-cs2` nadal wskazuje bdfe887. Istniejąca lokalna zmiana player_state.go pozostaje zachowana.

**Pomiar całego parsowania po ostatniej adaptacji**

Go 1.27.1, Apple M5, po 3 naprzemienne przebiegi bazowego d170961 i kandydata na demo, bez równoległego uruchamiania parserów. Tryb bare istniejącego harnessu audytowego (bez konsumenta i bez dodatkowych handlerów diagnostycznych, poza ServerInfo). Mediany czasu ParseToEnd:

| Demo | d170961 | Paczka | Skrócenie czasu |
|---|---:|---:|---:|
| Mirage | 11,973 s | 8,538 s | 28,7% |
| Anubis | 10,044 s | 6,539 s | 34,9% |

Łączne alokacje zmieniły się nieznacznie: około 4,119 → 4,100 GB oraz 3,130 → 3,118 GB (TotalAlloc, nie pamięć szczytowa). Wcześniejsza seria miała znacznie niższe czasy bezwzględne, więc obciążenie komputera wpływa na wyniki; nie jest to gwarancja przyspieszenia pełnej aplikacji. Wszystkie 12 przebiegów zakończyło się bez błędu. Surowe pomiary tej serii: `/tmp/demoinfocs-bulk-benchmark-final.json`; harness: `/tmp/demoinfocs-upstream-audit-20260922/audit-fork.go`.
