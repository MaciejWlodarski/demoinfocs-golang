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

**Etap 2: transport wiadomości i błędne dane**

Pierwszą paczkę zapisano jako `4a60032`. Kolejna paczka przenosi pooling buforów ramek i zagnieżdżonych wiadomości z `227d6f7`, poprawny rozmiar scratch Snappy i gobitread v0.2.5 z `a13e82b`, pooling bitreadera (`b4de502`), zatrzymanie callbacków po pierwszym błędzie (`f6d86d5`), kontrolę indeksów i wielkości kolekcji (`7d71cbb`) oraz kontrolę rozmiaru readBytes przed alokacją (`0d4e337`). Pozostałe fragmenty tych commitów nie są automatycznie uznawane za przeniesione.

Adaptacje: kontrola readBytes uwzględnia bajty już pobrane przez Huffman lookahead; bufor zagnieżdżonej wiadomości jest zwracany także przy błędzie; długość jest sprawdzana względem pozostałej zawartości pakietu przed alokacją. Po aktualizacji gobitread jawnie wykrywamy krótki odczyt ramki jako unexpected EOF. Zachowano kolejność priorytetów wiadomości i snapshoty skinów. Nie dodano obsługi transmisji CSTV ani szyfrowanych wiadomości.

Weryfikacja: testy z race PASS; dwa przebiegi każdego demo w golden PASS; pełne JSON-y konsumenta dla obu dem PASS względem niezmienionego d170961. Testy jednostkowe obejmują własność bajtów po ponownym użyciu bufora, kolejkę po błędzie, zachowanie pierwszego błędu, uszkodzone długości/indeksy i odczyt po lookahead.

**Etap 3: zgodne dodatki publicznego API**

Druga paczka jest zapisana jako `8a4baed`. Przeniesiono:

| Źródło | Zakres |
|---|---|
| `4e49895`, `c8786da` | nil receiver w PlayerPawnEntity oraz brak encji/właściwości w EquipmentValueCurrent; dodatkowo obsłużono pustą wartość właściwości |
| `6551a15` | publiczne ActiveWeaponID jako wrapper dotychczasowej funkcji, bez zmiany logiki ActiveWeapon |
| `6fd4f47` | FlashbangCount jako wrapper istniejącego Flashbangs |
| `20e6497` | ViewmodelOffset i ViewmodelFOV, dostosowane do forka obsługującego CS2 |
| `d948d9a` | FrameCount: -1 zanim znana jest łączna liczba klatek; rozszerzenie interfejsu Parser |
| `bf2c9b4` częściowo | typy i mapy modeli noży oraz MapKnifeType wraz z testami; bez zmiany zdarzeń/Equipment i bez OriginalString |

Weryfikacja: wszystkie krótkie testy z race PASS; golden obu dem PASS; pełny konsument na obu demach PASS (bez zmiany wzorców). Rozszerzenie interfejsu Parser wymaga dodania FrameCount w zewnętrznych ręcznych mockach, jeśli takie istnieją; aktualny konsument kompiluje się poprawnie.

**Pozostałe obszary — nie są zakończonym merge’em**

| Obszar | Ocena po tych paczkach |
|---|---|
| Nazwy właściwości send-node, kolekcje, typy wektorów | Świadomie zachowane zachowanie forka; pełne wersje upstreamu powodowały wykazane regresje |
| Klasyfikacja PlayerHurt/obrażeń bomby, kolejność zdarzeń i WeaponFire | Pozostawione: audyt wykazał inne klasyfikacje i ticki na tych samych demach |
| Powiązanie ofiar flasha, granatów, deterministyczne IDs, nowe eventy | Pozostają do osobnej oceny względem FakePlayerFlashed i własnego stanu/zdarzeń forka; nie uznano ich automatycznie za niemożliwe |
| Naprawa rekurencji getThrownGrenade (`b1ebbb3`) | Nie dotyczy obecnego forka: jego implementacja nie używa tej rekurencji |
| UserCmd i stan przycisków | Oddzielna funkcjonalność; fork rejestruje typ wiadomości, ale nie ma pełnej nowej warstwy usercmd upstreamu. Brak testowego korpusu dla tego przypadku |
| Protokoły protobuf / wiadomości szyfrowane | Nie przeniesione; wymagają spójnej aktualizacji generowanych typów i ścieżki deszyfrowania. Dwa aktualne GOTV nie testują deszyfrowania |
| Usunięcie API v4, zmiany modułu v5/v6, historia CS:GO/CSTV | Nie przeniesione do używanego API forka |
| CI, dokumentacja, przykłady, pozostałe testy upstreamu | Inwentarz istnieje; nie jest to kompletne odtworzenie infrastruktury upstreamu |

Git nadal może pokazywać 319 commitów upstream-only względem starej wspólnej bazy: backporty zapisano jako nowe lokalne commity, bez dopisywania nieprzeniesionej historii upstreamu jako przodka. Liczba ta nie mierzy ilości już przeniesionego kodu. Branch nie został wypchnięty, a przypięcie parsera w aplikacji nie zostało zmienione.

**Etap 4: przypisywanie flashów, granatów, atakującego i ostrzeżenia**

Źródła: `4126b7b` (flashe), `f06cb5a` (attacker_pawn), `30fcf79` (brakujące Entity/Owner granatu), `6248488` (dispatcher ostrzeżeń). Adaptacje zachowują własny FakePlayerFlashed z Duration i pierwszeństwo LastThrownGrenade.

- Flashe: ofiary są buforowane w obrębie klatki i dopasowywane do pocisku, który rzeczywiście eksplodował. Pusty wybuch nie usuwa innego granatu. Jawny znacznik detonacji odróżnia niewybuchnięty flash od wybuchu w klatce 0. Jeśli kilka flashów wybucha jednocześnie, najbliższa pozycja jest heurystyką upstreamu — nie dowodem fizycznej przyczynowości.
- PlayerHurt: brakujący atakujący jest szukany po attacker_pawn; rozpoznany user ID ma pierwszeństwo. Bez zmiany klasyfikacji obrażeń, ich wartości i kolejności.
- Granaty: ostatnio znana encja broni jest zapamiętywana przy zmianach ekwipunku lub właściciela, bez skanowania wszystkich graczy co tick. Snapshot chroni przed późniejszym nadpisaniem Owner/State. Używany tylko gdy dotychczasowa ścieżka LastThrownGrenade nie ma encji; kopia WeaponInstance ma właściciela zgodnego z rzucającym. Zapamiętana encja może być już zniszczona, jeśli usunięto ją z ekwipunku przed utworzeniem pocisku.
- Ostrzeżenia o nieznanym wyposażeniu trafiają do eventDispatcher. Ten sam problem naprawiono dla nieznanych wiadomości protobuf, ale przez kolejkę msgQueue: bezpośrednie wywołanie eventDispatcher z goroutine odczytu powodowało równoległe callbacki i zostało odrzucone podczas testów.

**Rozliczenie zmian wyników**

Zachowano wcześniejsze wzorce w `pkg/demoinfocs/testdata/gotv/before-event-backports/`. Nowe oczekiwania wprowadzono dopiero po porównaniu pełnych JSON-ów i śladu wszystkich 657 rzutów na Mirage. Zapis dowodów: `pkg/demoinfocs/testdata/gotv/event-backports-evidence.json`.

| Wynik | Zmiana |
|---|---|
| Mirage, tick 237119, pocisk 522, smoke gracza 76561198724978523 | WeaponInstance: brak encji/Owner i EntityId=0 → encja 167 i właściwy Owner. ItemNewOwner w ticku 232403 potwierdza właściciela encji 167; jej sieciowe m_flThrowStrength wynosi 1 |
| Pełny JSON aplikacji na Mirage | Dokładnie jedno pole: rounds[29].events.grenades[27].throw_strength: 0 → 1. Indeks granatu aplikacji 1062 nie jest ID encji pocisku |
| Pełny JSON aplikacji na Anubisie | Bez zmian |
| Pozostałe 656 rzutów na Mirage | Bez zmian w śladzie tick/pocisk/typ/encja/Owner/rzucający/siła |
| Golden biblioteki | Zmieniony tylko hash GrenadeProjectileThrow na Mirage (EntityId odzyskanej broni) oraz nowe liczniki ParserWarn; pozostałe hashe, wyniki, klatki i liczniki eventów bez zmian |
| Nowo widoczne ParserWarn | 74 na Mirage, 42 na Anubisie, wszystkie dla dotychczas pomijanej wiadomości 389 / CS_UM_WeaponMagDrop. Sama obsługa tej wiadomości nie została dodana |

W obu demach nie wystąpiła zmiana wyników flashowania ani PlayerHurt. Test niezależny od hashy potwierdził zgodność 364 FakePlayerFlashed na Mirage i 192 na Anubisie z rzeczywistymi wybuchami tych samych pocisków i rzucających w tej samej klatce. Przypadki naprawiane poza tym korpusem pokrywają testy syntetyczne: wybuch poza kolejnością, wybuch bez ofiar, oba porządki aktualizacji w klatce, wiele wybuchów naraz, klatka 0, brak user ID, nieznany pawn handle, snapshot granatu po usunięciu i dostarczanie obu kategorii ostrzeżeń.

Weryfikacja: krótkie testy z race PASS; oba testy GOTV (golden i niezależne przypisanie) po dwa przebiegi PASS; pełne wyniki konsumenta PASS względem przejrzanych oczekiwań. Nie usuwano żadnych pól przy porównaniu JSON. Oryginalny projekt konsumenta i przypięcie jego biblioteki pozostają bez zmian.

Dodatkowy pełny przebieg Mirage z `-race`, obejmujący nowe ostrzeżenia i porównanie golden: PASS (132,744 s). `git diff --check`: PASS.
