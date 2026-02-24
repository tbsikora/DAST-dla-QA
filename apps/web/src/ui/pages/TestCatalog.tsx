import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  Drawer,
  Grid,
  Paper,
  Skeleton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import IconButton from "@mui/material/IconButton";

const API = import.meta.env.VITE_API_URL ?? "";
type TestCatalogItem = {
  id:
    | "SQLi"
    | "XSS"
    | "PATH_TRAVERSAL"
    | "TEMPLATE_INJECTION"
    | "SSRF"
    | "HEADER_INJECTION"
    | "OPEN_REDIRECT"
    | "FUZZ"
    | "AUTH"
    | "RATE_LIMIT";
  name: string;
  short: string;
  category: "Detekcja podatności" | "Kontrola dostępu" | "Odporność / walidacja" | "Kontrole operacyjne";
  uiVisible: boolean;
  engineEnabled: boolean;
  cost: "Niski" | "Średni" | "Wyższy";
  scope: string[];
  goal: string;
  mechanism: string[];
  verdicts: string[];
  falsePositiveControls: string[];
  limitations: string[];
  evidenceExamples: string[];
  settings: string[];
  valueAssessment: string;
  phase2: string[];
};

const TESTS: TestCatalogItem[] = [
  {
    id: "SQLi",
    name: "SQL Injection",
    short: "Wykrywanie podatności SQL Injection na podstawie anomalii odpowiedzi serwera, komunikatów błędów oraz zmian czasu odpowiedzi.",
    category: "Detekcja podatności",
    uiVisible: true,
    engineEnabled: true,
    cost: "Wyższy",
    scope: ["Parametry query", "Parametry path", "Body żądania", "Wybrane pola nagłówków HTTP (w ograniczonym zakresie)"],
    goal: "Identyfikacja podatności SQL Injection (error-based oraz blind: time-based i boolean-based).",
    mechanism: [
      "Generowanie payloadów SQL Injection na podstawie parametrów zdefiniowanych w specyfikacji OpenAPI.",
      "Wykonanie żądania referencyjnego (linii bazowej) dla danego endpointu.",
      "Wykonanie żądań testowych z payloadami SQLi i porównanie odpowiedzi z linią bazową.",
      "Detekcja komunikatów błędów bazy danych (np. błędów składni SQL lub komunikatów sterowników baz danych).",
      "Detekcja blind time-based poprzez porównanie czasu odpowiedzi z odpowiedzią referencyjną.",
      "Detekcja blind boolean-based poprzez modyfikację warunku logicznego w parametrze i porównanie kodu statusu oraz rozmiaru odpowiedzi."
    ],
    verdicts: [
      "Podejrzane: wykryto charakterystyczny komunikat błędu SQL lub powtarzalną anomalię odpowiedzi wskazującą na SQL Injection.",
      "Niejednoznaczne: niestabilna linia bazowa, brak odpowiedzi referencyjnej lub losowe błędy serwera (5xx).",
      "OK: brak istotnych różnic między odpowiedzią testową a referencyjną.",
      "Błąd: problem transportowy, przekroczenie czasu oczekiwania lub brak odpowiedzi."
    ],
    falsePositiveControls: [
      "Porównanie odpowiedzi do linii bazowej dla każdego endpointu i metody HTTP.",
      "Oznaczenie wyniku jako niejednoznaczny przy niestabilnej odpowiedzi referencyjnej.",
      "Oddzielna analiza wyników time-based i boolean-based.",
      "Opcjonalna weryfikacja struktury odpowiedzi względem schematu kontraktu API."
    ],
    limitations: [
      "Test nie ma wglądu w bazę danych ani logi serwera, dlatego nie potwierdza podatności po stronie backendu.",
      "Nietypowe komunikaty błędów mogą nie zostać rozpoznane.",
      "Metoda time-based może być podatna na zmienny czas odpowiedzi środowiska."
    ],
    evidenceExamples: [
      "Fragment odpowiedzi zawierający komunikat błędu SQL.",
      "Różnica czasu odpowiedzi względem linii bazowej.",
      "Różnica kodu statusu lub rozmiaru odpowiedzi między wariantami logicznymi."
    ],
    settings: ["Intensywność testów", "Response validation", "Limit testów", "Concurrency", "Throttle"],
    valueAssessment: "Wysoka wartość. To jeden z kluczowych testów bezpieczeństwa dla API z warstwą danych.",
    phase2: [
      "Rozszerzenie payloadów per silnik DB (MySQL/PostgreSQL/MSSQL/Oracle).",
      "Lepsze score confidence rozdzielające error-based vs blind.",
      "Korelacja z parametrami typowanymi jako identyfikatory / filtry / sortowanie."
    ]
  },
  {
    id: "XSS",
    name: "Cross-Site Scripting",
    short: "Wykrywanie niebezpiecznego odbicia danych wejściowych w odpowiedzi serwera, które może prowadzić do podatności XSS po stronie klienta.",
    category: "Detekcja podatności",
    uiVisible: true,
    engineEnabled: true,
    cost: "Średni",
    scope: ["Parametry query", "Parametry path", "Body"],
    goal: "Identyfikacja przypadków, w których dane przekazane w żądaniu są zwracane w odpowiedzi bez odpowiedniego filtrowania lub kodowania.",
    mechanism: [
      "Generowanie testowych payloadów XSS dla parametrów wejściowych.",
      "Wysłanie żądania referencyjnego (linii bazowej).",
      "Wysłanie żądań testowych z payloadem i sprawdzenie, czy dane wejściowe zostały odzwierciedlone w odpowiedzi.",
      "Określenie typu odpowiedzi na podstawie nagłówka `Content-Type`.",
      "Analiza kontekstu odbicia: tekst, HTML lub dane strukturalne (np. JSON).",
      "Oznaczenie jako bardziej ryzykowne przypadków, gdy payload pojawia się w treści HTML bez kodowania znaków specjalnych."
    ],
    verdicts: [
      "Podejrzane: dane wejściowe pojawiają się w odpowiedzi HTML bez odpowiedniego kodowania znaków.",
      "Niejednoznaczne: dane wejściowe odbite w JSON lub w kontekście niepozwalającym jednoznacznie ocenić ryzyka.",
      "OK: brak odbicia danych wejściowych lub dane są prawidłowo zakodowane.",
      "Błąd: problem transportowy lub brak odpowiedzi."
    ],
    falsePositiveControls: [
      "Rozróżnienie odpowiedzi HTML i JSON na podstawie nagłówków HTTP.",
      "Analiza kodowania znaków specjalnych (np. `<`, `>`, `\"`, `'`).",
      "Porównanie z odpowiedzią referencyjną (linią bazową)."
    ],
    limitations: [
      "Test nie uruchamia kodu JavaScript w przeglądarce — ocenia tylko potencjalne ryzyko.",
      "Możliwe pominięcia w złożonych mechanizmach szablonów lub niestandardowym kodowaniu danych."
    ],
    evidenceExamples: [
      "Fragment odpowiedzi zawierający odbity payload.",
      "Informacja o typie odpowiedzi (HTML/JSON) oraz sposobie zakodowania danych."
    ],
    settings: ["Intensywność testów", "Response validation", "Concurrency", "Throttle"],
    valueAssessment: "Wysoka wartość, szczególnie dla endpointów zwracających HTML lub fragmenty renderowane przez frontend.",
    phase2: [
      "Lepsza klasyfikacja kontekstów (atribut, script, URL, HTML text node).",
      "Opcjonalna weryfikacja browser-based dla wybranych przypadków.",
      "Lepsze wykrywanie encoding bypass (HTML/URL/JS escaping)."
    ]
  },
  {
    id: "PATH_TRAVERSAL",
    name: "Path Traversal",
    short: "Wykrywanie prób odczytu plików spoza dozwolonego katalogu aplikacji poprzez manipulację ścieżką pliku.",
    category: "Detekcja podatności",
    uiVisible: false,
    engineEnabled: true,
    cost: "Średni",
    scope: ["Parametry query", "Parametry path", "Body (wybrane pola zawierające ścieżki plików)"],
    goal: "Identyfikacja przypadków, w których aplikacja umożliwia dostęp do plików systemowych lub konfiguracyjnych po modyfikacji parametrów ścieżki.",
    mechanism: [
      "Generowanie sekwencji przejścia katalogów (np. ../, ..\\\\) oraz ich zakodowanych odpowiedników URL (np. %2e%2e%2f).",
      "Wysyłanie żądań zawierających nazwy charakterystycznych plików systemowych (np. /etc/passwd, win.ini).",
      "Analiza odpowiedzi w poszukiwaniu wzorców treści wskazujących na odczyt pliku systemowego.",
      "Odróżnienie rzeczywistej treści pliku od prostego odbicia danych wejściowych w odpowiedzi.",
      "Porównanie z odpowiedzią referencyjną (linią bazową), aby wykryć istotne zmiany po użyciu payloadu."
    ],
    verdicts: [
      "Podejrzane: odpowiedź zawiera fragmenty charakterystyczne dla pliku systemowego po użyciu zmodyfikowanej ścieżki.",
      "Niejednoznaczne: błędy serwera, niestabilna odpowiedź lub różnice bez jednoznacznego potwierdzenia odczytu pliku.",
      "OK: brak oznak odczytu pliku.",
      "Błąd: problem transportowy lub brak odpowiedzi."
    ],
    falsePositiveControls: [
      "Wymagane są sygnatury treści pliku systemowego, a nie samo odbicie payloadu.",
      "Pomijanie odpowiedzi zawierających jedynie przesłaną wartość parametru.",
      "Porównanie z odpowiedzią referencyjną (linią bazową)."
    ],
    limitations: [
      "Test wykrywa tylko przypadki, w których treść pliku pojawia się w odpowiedzi.",
      "Zakres wykrywania zależy od znanych sygnatur plików systemowych.",
      "Nie wykrywa przypadków, w których aplikacja odczytuje plik bez zwracania jego treści w odpowiedzi."
    ],
    evidenceExamples: [
      "Fragment odpowiedzi odpowiadający zawartości /etc/passwd.",
      "Fragment odpowiedzi odpowiadający zawartości win.ini.",
      "Struktura danych wskazująca na odczyt pliku w odpowiedzi JSON."
    ],
    settings: ["Intensywność testów", "Response validation", "Concurrency", "Throttle"],
    valueAssessment: "Średnio-wysoka wartość dla API pracujących na plikach, eksportach, preview i endpointach dokumentów.",
    phase2: [
      "Rozszerzenie sygnatur plików systemowych i framework-specific leak fingerprints.",
      "Lepsze targetowanie pól nazwanych file/path/template/source."
    ]
  },
  {
    id: "TEMPLATE_INJECTION",
    name: "Server-Side Template Injection",
    short: "Wykrywanie przypadków, w których dane wejściowe użytkownika są interpretowane jako wyrażenia w silniku szablonów po stronie serwera.",
    category: "Detekcja podatności",
    uiVisible: false,
    engineEnabled: true,
    cost: "Średni",
    scope: ["Parametry query", "Parametry path", "Body żądania"],
    goal: "Identyfikacja sytuacji, w których aplikacja renderuje dane użytkownika w szablonie bez odpowiedniego filtrowania lub escapowania.",
    mechanism: [
      "Wysyłanie payloadów zawierających wyrażenia typowe dla silników szablonów (np. `7*7` w odpowiedniej składni).",
      "Wykonanie żądania referencyjnego (linii bazowej).",
      "Sprawdzenie, czy w odpowiedzi pojawia się wynik obliczenia zamiast oryginalnego tekstu payloadu.",
      "Analiza odpowiedzi pod kątem oznak przetwarzania danych przez silnik szablonów.",
      "Porównanie odpowiedzi z odpowiedzią referencyjną (linią bazową)."
    ],
    verdicts: [
      "Podejrzane: odpowiedź zawiera wynik obliczenia wyrażenia, co wskazuje na interpretację danych wejściowych przez szablon.",
      "Niejednoznaczne: zmiany w odpowiedzi bez jednoznacznego potwierdzenia wykonania wyrażenia.",
      "OK: payload pojawia się jako zwykły tekst lub jest usuwany.",
      "Błąd: problem transportowy lub brak odpowiedzi."
    ],
    falsePositiveControls: [
      "Wymagane pojawienie się wyniku obliczenia zamiast dosłownego tekstu payloadu.",
      "Porównanie z odpowiedzią referencyjną (linią bazową).",
      "Ignorowanie przypadków, gdy odpowiedź zawiera stałą wartość niezależną od payloadu."
    ],
    limitations: [
      "Test opiera się na heurystyce i nie obejmuje wszystkich składni silników szablonów.",
      "Może nie wykryć podatności w środowiskach z silnym sandboxem lub niestandardowym filtrowaniem danych."
    ],
    evidenceExamples: [
      "Fragment odpowiedzi zawierający wynik obliczenia (np. `49` zamiast `7*7`).",
      "Zmiana struktury odpowiedzi wskazująca na przetwarzanie danych przez szablon."
    ],
    settings: ["Intensywność testów", "Response validation", "Concurrency", "Throttle"],
    valueAssessment: "Średnia wartość, dobra jako dodatkowa warstwa wykrywania w aplikacjach z renderowaniem szablonów.",
    phase2: [
      "Wielosilnikowe payloady (Jinja2, Twig, Freemarker, Velocity, Handlebars variants).",
      "Lepsze profile payloadów zależne od stacku technologicznego."
    ]
  },
  {
    id: "SSRF",
    name: "Server-Side Request Forgery",
    short: "Wykrywanie sytuacji, w których serwer wykonuje żądania HTTP na podstawie danych przekazanych przez użytkownika.",
    category: "Detekcja podatności",
    uiVisible: false,
    engineEnabled: true,
    cost: "Średni",
    scope: ["Parametry zawierające adresy URL lub URI w query, path lub body."],
    goal: "Identyfikacja przypadków, w których aplikacja może uzyskiwać dostęp do zasobów wewnętrznych lub usług lokalnych na podstawie przekazanego adresu URL.",
    mechanism: [
      "Wysyłanie żądań z kontrolowanymi adresami URL wskazującymi zasoby lokalne (np. `127.0.0.1`, `localhost`).",
      "Testy z adresami charakterystycznymi dla usług metadanych środowisk chmurowych (np. `169.254.169.254`).",
      "Analiza odpowiedzi serwera pod kątem oznak pobrania zasobu wewnętrznego (np. fragmenty konfiguracji, identyfikatory instancji, dane systemowe).",
      "Sprawdzenie, czy odpowiedź zawiera dane pochodzące z adresu przekazanego w parametrze.",
      "Porównanie z odpowiedzią referencyjną (linią bazową) w celu wykrycia istotnych zmian."
    ],
    verdicts: [
      "Podejrzane: odpowiedź zawiera dane wskazujące na dostęp do zasobu lokalnego powiązanego z użytym adresem.",
      "Niejednoznaczne: różnice w odpowiedzi bez jednoznacznego potwierdzenia pobrania zasobu.",
      "OK: brak oznak wykonania żądania do wskazanego zasobu.",
      "Błąd: problem transportowy lub brak odpowiedzi."
    ],
    falsePositiveControls: [
      "Wymagane jest powiązanie danych w odpowiedzi z użytym adresem URL.",
      "Porównanie z odpowiedzią referencyjną (linią bazową).",
      "Ignorowanie statycznych komunikatów błędów niezależnych od payloadu."
    ],
    limitations: [
      "Test nie wykorzystuje technik out-of-band (`OAST`), dlatego nie wykrywa przypadków SSRF bez widocznego efektu w odpowiedzi.",
      "Nie wszystkie usługi wewnętrzne zwracają dane możliwe do identyfikacji w odpowiedzi."
    ],
    evidenceExamples: [
      "Fragment odpowiedzi zawierający dane z lokalnego hosta.",
      "Dane charakterystyczne dla usług metadanych środowiska chmurowego."
    ],
    settings: ["Intensywność testów", "Response validation", "Concurrency", "Throttle"],
    valueAssessment: "Średnio-wysoka wartość, szczególnie dla API integracyjnych i endpointów pobierających URL-e.",
    phase2: [
      "Integracja OAST (callback/DNS/HTTP) dla potwierdzania SSRF poza odpowiedzią.",
      "Lepsze wykrywanie przez klasyfikację pól typu URL w schemacie."
    ]
  },
  {
    id: "HEADER_INJECTION",
    name: "CRLF Injection",
    short: "Wykrywanie możliwości wpływu danych wejściowych użytkownika na nagłówki odpowiedzi HTTP.",
    category: "Detekcja podatności",
    uiVisible: false,
    engineEnabled: true,
    cost: "Średni",
    scope: ["Parametry query, path oraz body, które mogą być używane przez aplikację przy generowaniu odpowiedzi HTTP."],
    goal: "Wykrywanie przypadków, w których dane przekazane w żądaniu mogą spowodować wstrzyknięcie lub modyfikację nagłówków HTTP (header injection / response splitting).",
    mechanism: [
      "Wysyłanie żądań zawierających specjalne znaczniki testowe oraz sekwencje znaków nowej linii (`CRLF`).",
      "Analiza nagłówków odpowiedzi HTTP po wykonaniu żądań testowych.",
      "Sprawdzenie, czy dane wejściowe pojawiają się w nagłówkach odpowiedzi (np. `Location`, `Set-Cookie`, `Content-Disposition`).",
      "Wykrywanie pojawienia się nowych lub zmodyfikowanych nagłówków po użyciu payloadu.",
      "Porównanie odpowiedzi z odpowiedzią referencyjną (linią bazową)."
    ],
    verdicts: [
      "Podejrzane: w odpowiedzi pojawia się nowy nagłówek lub zmodyfikowana wartość nagłówka zawierająca dane wejściowe.",
      "Niejednoznaczne: różnice w nagłówkach bez jednoznacznego powiązania z payloadem lub niestabilna linia bazowa.",
      "OK: brak wpływu danych wejściowych na nagłówki odpowiedzi.",
      "Błąd: problem transportowy lub brak odpowiedzi."
    ],
    falsePositiveControls: [
      "Wymagane powiązanie danych wejściowych z konkretnym nagłówkiem odpowiedzi.",
      "Porównanie z odpowiedzią referencyjną (linią bazową).",
      "Pomijanie standardowych, niezmiennych nagłówków generowanych przez serwer."
    ],
    limitations: [
      "Test opiera się na analizie odpowiedzi HTTP i nie potwierdza pełnego wykorzystania podatności w przeglądarce.",
      "Wymaga widocznego śladu w nagłówkach odpowiedzi."
    ],
    evidenceExamples: [
      "Lista nagłówków odpowiedzi zawierająca dodatkowy lub zmodyfikowany nagłówek.",
      "Wartość nagłówka zawierająca znacznik payloadu."
    ],
    settings: ["Intensywność testów", "Response validation", "Concurrency", "Throttle"],
    valueAssessment: "Średnia wartość. Przydatne jako wczesne ostrzeżenie, ale wyniki wymagają ręcznej weryfikacji.",
    phase2: [
      "Rozszerzenie o bardziej realistyczne payloady CRLF i analizę wielowartościowych nagłówków.",
      "Lepsze rozróżnienie echa biznesowego vs wpływu na strukturę odpowiedzi HTTP."
    ]
  },
  {
    id: "OPEN_REDIRECT",
    name: "Open Redirect",
    short: "Wykrywanie przekierowań 3xx na zewnętrzny host kontrolowany przez payload.",
    category: "Detekcja podatności",
    uiVisible: false,
    engineEnabled: true,
    cost: "Niski",
    scope: ["Parametry redirect/next/url/returnTo w query/body/path"],
    goal: "Identyfikacja podatności Open Redirect poprzez analizę `Location`.",
    mechanism: [
      "Generowanie payloadów URL/host dla potencjalnych parametrów przekierowań.",
      "Wymagany status 3xx oraz nagłówek `Location`.",
      "Korelacja `Location` z payloadem i weryfikacja hosta zewnętrznego względem targetu."
    ],
    verdicts: [
      "Podejrzane: 3xx + `Location` wskazuje zewnętrzny host powiązany z payloadem.",
      "Niejednoznaczne: 3xx bez mocnego dowodu zewnętrznego przekierowania lub niestabilna linia bazowa.",
      "OK: brak sygnału.",
      "Błąd: problem transportowy."
    ],
    falsePositiveControls: [
      "Porównanie hosta targetu i hosta w `Location`.",
      "Wymóg korelacji z payloadem."
    ],
    limitations: [
      "Nie obejmuje JS-based redirects bez `Location`.",
      "Może nie wykryć bardziej złożonych bypassów walidacji URL."
    ],
    evidenceExamples: ["Nagłówek `Location` z hostem zewnętrznym", "Status 302/303/307"],
    settings: ["Intensywność testów", "Response validation", "Concurrency", "Throttle"],
    valueAssessment: "Średnio-wysoka wartość przy niskim koszcie wykonania.",
    phase2: [
      "Lepsze payloady bypass (schemes, double-encoding, protocol-relative, mixed case).",
      "Wykrywanie redirect chain i finalnego celu."
    ]
  },
  {
    id: "FUZZ",
    name: "Input Validation",
    short: "Sprawdzanie, czy endpointy poprawnie obsługują nieprawidłowe dane wejściowe zgodnie ze zdefiniowanym kontraktem API.",
    category: "Odporność / walidacja",
    uiVisible: true,
    engineEnabled: true,
    cost: "Wyższy",
    scope: ["Parametry query", "Parametry path", "Body JSON oraz pola formularzy"],
    goal: "Wykrywanie braku walidacji danych oraz sytuacji, w których niepoprawne dane powodują błędy serwera lub niestabilne działanie aplikacji.",
    mechanism: [
      "Generowanie nieprawidłowych wartości na podstawie schematu OpenAPI (typ, zakres, format, wartości enum).",
      "Wysyłanie żądań z danymi niezgodnymi z kontraktem API (np. zły typ, brak wymaganych pól, wartości spoza zakresu).",
      "Analiza kodów odpowiedzi HTTP.",
      "Wykrywanie błędów serwera (5xx) oraz istotnych zmian odpowiedzi względem odpowiedzi referencyjnej (linii bazowej)."
    ],
    verdicts: [
      "Podejrzane: niepoprawne dane powodują błąd serwera (5xx) lub poważną anomalię odpowiedzi.",
      "Niejednoznaczne: niestabilna odpowiedź lub niejednoznaczna reakcja serwera.",
      "OK: aplikacja poprawnie odrzuca dane (np. kod 4xx).",
      "Błąd: problem transportowy lub brak odpowiedzi."
    ],
    falsePositiveControls: [
      "Porównanie z odpowiedzią referencyjną (linią bazową).",
      "Ograniczenie liczby i złożoności przypadków testowych.",
      "Grupowanie powtarzających się wyników."
    ],
    limitations: [
      "Wynik nie zawsze oznacza podatność bezpieczeństwa, często wskazuje problem jakości lub obsługi błędów.",
      "Test nie analizuje poprawności logiki biznesowej ani znaczenia danych."
    ],
    evidenceExamples: [
      "Kod odpowiedzi 500 po przesłaniu niepoprawnej wartości.",
      "Istotna zmiana treści lub rozmiaru odpowiedzi."
    ],
    settings: ["Fuzz depth", "Body field limit", "Intensywność testów", "Response validation"],
    valueAssessment: "Średnia wartość. Bardzo przydatne do hardeningu API i wykrywania słabej walidacji.",
    phase2: [
      "Profile fuzzingu per typ danych i typ endpointu.",
      "Lepsze raportowanie różnic kontraktowych i klasyfikacja podatność vs bug jakościowy."
    ]
  },
  {
    id: "AUTH",
    name: "Broken Access Control",
    short: "Sprawdzenie, czy endpointy oznaczone jako chronione wymagają poprawnej autoryzacji.",
    category: "Kontrola dostępu",
    uiVisible: true,
    engineEnabled: true,
    cost: "Niski",
    scope: ["Endpointy, które w specyfikacji OpenAPI mają zdefiniowane pole `security`."],
    goal: "Wykrywanie przypadków, w których endpoint jest dostępny bez uwierzytelnienia lub bez skutecznej kontroli uprawnień.",
    mechanism: [
      "Wybór endpointów z deklaracją `security` w specyfikacji.",
      "Wykonanie żądania referencyjnego (linii bazowej) z poprawną autoryzacją.",
      "Wykonanie tego samego żądania bez nagłówków autoryzacji (np. usunięcie `Authorization` / tokenu).",
      "Porównanie odpowiedzi: jeśli odpowiedź bez autoryzacji jest podobna do odpowiedzi referencyjnej lub zwraca kod sukcesu (`2xx`), endpoint może nie egzekwować autoryzacji."
    ],
    verdicts: [
      "Podejrzane: endpoint zwraca poprawną odpowiedź mimo braku autoryzacji.",
      "Niejednoznaczne: odpowiedź serwera jest niestabilna lub brak poprawnej odpowiedzi referencyjnej.",
      "OK: brak autoryzacji skutkuje odmową dostępu (`401` lub `403`).",
      "Błąd: błąd transportu lub brak odpowiedzi serwera."
    ],
    falsePositiveControls: [
      "Testowane są wyłącznie endpointy oznaczone `security` w OpenAPI.",
      "Odpowiedź bez autoryzacji jest porównywana z odpowiedzią referencyjną (linią bazową)."
    ],
    limitations: [
      "Jeśli specyfikacja OpenAPI nie definiuje `security`, endpoint nie zostanie przetestowany.",
      "Test nie wykrywa złożonych błędów autoryzacji zależnych od ról lub własności danych (np. `BOLA` / dostęp do danych innego użytkownika)."
    ],
    evidenceExamples: [
      "Kod odpowiedzi HTTP zwrócony bez autoryzacji.",
      "Fragment odpowiedzi zwrócony mimo braku wymaganych uprawnień."
    ],
    settings: ["Throttle", "Concurrency", "Zachowanie linii bazowej"],
    valueAssessment: "Wysoka wartość. Bardzo praktyczny test na realne luki egzekwowania auth.",
    phase2: [
      "Testy per rola/zakres (authorization, nie tylko authentication).",
      "Profile negative auth dla Bearer/API key/JWT i warianty tokenów wygasłych/niepoprawnych."
    ]
  },
  {
    id: "RATE_LIMIT",
    name: "Rate Limit Bypass",
    short: "Sprawdzanie, czy endpointy posiadają mechanizm ograniczania liczby zapytań oraz jak reagują na krótkotrwałe zwiększenie ruchu.",
    category: "Kontrole operacyjne",
    uiVisible: true,
    engineEnabled: true,
    cost: "Wyższy",
    scope: ["Wybrane endpointy identyfikowane na podstawie nazw sugerujących operacje wrażliwe (np. login, auth, token, password, otp)."],
    goal: "Identyfikacja przypadków braku lub niewłaściwego działania mechanizmu rate limiting na wrażliwych endpointach.",
    mechanism: [
      "Wybór kandydatów na podstawie nazw ścieżek endpointów.",
      "Wysłanie serii szybkich żądań (burst) w krótkim odstępie czasu.",
      "Analiza kodów odpowiedzi HTTP.",
      "Sprawdzenie występowania kodu 429 Too Many Requests lub opóźnienia odpowiedzi.",
      "Porównanie czasu odpowiedzi i statusów z odpowiedzią referencyjną (linią bazową)."
    ],
    verdicts: [
      "Podejrzane: brak reakcji ograniczającej (brak 429 i brak spowolnienia) przy wielu zapytaniach.",
      "OK: widoczna reakcja ograniczająca (kod 429 lub znaczące spowolnienie odpowiedzi).",
      "Niejednoznaczne: niestabilne odpowiedzi lub brak porównywalnej linii bazowej.",
      "Błąd: część żądań nie została wykonana lub wystąpił problem transportowy."
    ],
    falsePositiveControls: [
      "Porównanie wyników z odpowiedzią referencyjną (linią bazową).",
      "Ograniczenie liczby testowanych endpointów.",
      "Analiza zarówno kodów statusu, jak i czasu odpowiedzi."
    ],
    limitations: [
      "Test nie identyfikuje dokładnej polityki rate limit (np. per użytkownik, IP lub klucz API).",
      "Brak odpowiedzi 429 nie zawsze oznacza podatność bezpieczeństwa, a jedynie brak mechanizmu ochronnego.",
      "Nie analizuje szczegółowo nagłówków RateLimit-* ani Retry-After."
    ],
    evidenceExamples: [
      "Rozkład kodów odpowiedzi dla serii żądań.",
      "Wzrost lub brak wzrostu czasu odpowiedzi.",
      "Nagłówki odpowiedzi związane z ograniczaniem zapytań."
    ],
    settings: ["Throttle (globalny)", "Concurrency", "Intensywność pośrednio przez obciążenie skanu"],
    valueAssessment: "Średnia wartość. Dobry screening operacyjny, ale wymaga ręcznej interpretacji i dalszych testów.",
    phase2: [
      "Analiza nagłówków `Retry-After`, `X-RateLimit-*`.",
      "Profile burst i progressive ramp-up.",
      "Lepsza selekcja kandydatów z OpenAPI tags/operationId i metadanych auth."
    ]
  }
];

function categoryColor(category: TestCatalogItem["category"]) {
  if (category === "Detekcja podatności") return "error";
  if (category === "Kontrola dostępu") return "warning";
  if (category === "Odporność / walidacja") return "info";
  return "default";
}

type ManualVerification = {
  payload?: string;
  request?: string;
  responseCheck?: string;
};

type TestCatalogEntry = TestCatalogItem & {
  enabled: boolean;
};

type TestCatalogDetail = TestCatalogEntry & {
  manualVerification?: ManualVerification;
};

type SeverityLevel = "Krytyczne" | "Wysokie" | "Średnie" | "Niskie" | "Informacyjne";

function mapCategoryToType(category: TestCatalogItem["category"]) {
  if (category === "Detekcja podatności") return "Testy bezpieczeństwa";
  if (category === "Kontrola dostępu") return "Testy bezpieczeństwa";
  return "Testy jakości";
}

function getCatalogSeverity(id: TestCatalogItem["id"]): SeverityLevel {
  if (id === "SQLi") return "Krytyczne";
  if (id === "AUTH") return "Krytyczne";
  if (id === "TEMPLATE_INJECTION") return "Krytyczne";
  if (id === "XSS") return "Wysokie";
  if (id === "SSRF") return "Wysokie";
  if (id === "PATH_TRAVERSAL") return "Wysokie";
  if (id === "HEADER_INJECTION") return "Wysokie";
  if (id === "RATE_LIMIT") return "Średnie";
  if (id === "FUZZ") return "Informacyjne";
  return "Niskie";
}

function severityChipSx(level: SeverityLevel) {
  if (level === "Krytyczne") {
    return { color: "#B42318", borderColor: "rgba(180,35,24,0.38)", bgcolor: "rgba(180,35,24,0.12)", fontWeight: 700 };
  }
  if (level === "Wysokie") {
    return { color: "#C2410C", borderColor: "rgba(194,65,12,0.36)", bgcolor: "rgba(194,65,12,0.12)", fontWeight: 700 };
  }
  if (level === "Średnie") {
    return { color: "#A16207", borderColor: "rgba(161,98,7,0.34)", bgcolor: "rgba(161,98,7,0.12)", fontWeight: 700 };
  }
  if (level === "Niskie") {
    return { color: "#15803D", borderColor: "rgba(21,128,61,0.35)", bgcolor: "rgba(21,128,61,0.10)", fontWeight: 700 };
  }
  return { color: "#6B7280", borderColor: "rgba(107,114,128,0.32)", bgcolor: "rgba(107,114,128,0.10)", fontWeight: 700 };
}

function getCatalogSurfaceLabel(id: TestCatalogItem["id"]) {
  if (id === "SQLi") return "Dane wejściowe API";
  if (id === "XSS") return "Odpowiedź aplikacji";
  if (id === "SSRF") return "Pobieranie zasobów zewnętrznych";
  if (id === "AUTH") return "Mechanizm kontroli dostępu";
  if (id === "HEADER_INJECTION") return "Warstwa protokołu HTTP";
  if (id === "OPEN_REDIRECT") return "Mechanizm przekierowań";
  if (id === "PATH_TRAVERSAL") return "Obsługa plików i ścieżek";
  if (id === "TEMPLATE_INJECTION") return "Renderowanie odpowiedzi";
  if (id === "RATE_LIMIT") return "Mechanizm ograniczania żądań";
  if (id === "FUZZ") return "Walidacja danych wejściowych";
  return "Parametry";
}

function typeChipSx(category: TestCatalogItem["category"]) {
  const type = mapCategoryToType(category);
  if (type === "Testy bezpieczeństwa") {
    return {
      color: "#0F172A",
      borderColor: "rgba(15,23,42,0.16)",
      bgcolor: "#F1F5F9",
      fontWeight: 600
    };
  }
  if (type === "Testy jakości") {
    return {
      color: "#1D4ED8",
      borderColor: "rgba(29,78,216,0.20)",
      bgcolor: "#EFF6FF",
      fontWeight: 600
    };
  }
  return {
    color: "#334155",
    borderColor: "rgba(51,65,85,0.16)",
    bgcolor: "#F8FAFC",
    fontWeight: 600
  };
}

function sortCatalogItems(items: TestCatalogEntry[]) {
  const priority: Record<string, number> = { AUTH: 0, SQLi: 1, XSS: 2, SSRF: 3 };
  const typeOrder: Record<string, number> = {
    "Testy bezpieczeństwa": 0,
    "Testy jakości": 2
  };
  return [...items].sort((a, b) => {
    const typeA = mapCategoryToType(a.category);
    const typeB = mapCategoryToType(b.category);
    const ta = typeOrder[typeA] ?? 999;
    const tb = typeOrder[typeB] ?? 999;
    if (ta !== tb) return ta - tb;
    const pa = priority[a.id] ?? 999;
    const pb = priority[b.id] ?? 999;
    if (pa !== pb) return pa - pb;
    return a.name.localeCompare(b.name, "pl");
  });
}

function cloneTest(item: TestCatalogItem): TestCatalogEntry {
  return {
    ...item,
    enabled: item.engineEnabled
  };
}

const testCatalogApi = {
  async list(): Promise<TestCatalogEntry[]> {
    // Local source of truth for content; PATCH can override enabled status in cache.
    return sortCatalogItems(TESTS.map(cloneTest));
  },

  async getById(id: string): Promise<TestCatalogDetail> {
    const local = TESTS.find((t) => t.id === id);
    if (!local) throw new Error("Nie znaleziono testu.");

    try {
      const res = await fetch(`${API}/api/tests/${encodeURIComponent(id)}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return cloneTest(local);
      }

      const manualVerificationRaw = data?.manualVerification ?? {};
      const manualVerification =
        manualVerificationRaw && typeof manualVerificationRaw === "object"
          ? {
              payload: typeof manualVerificationRaw.payload === "string" ? manualVerificationRaw.payload : undefined,
              request: typeof manualVerificationRaw.request === "string" ? manualVerificationRaw.request : undefined,
              responseCheck:
                typeof manualVerificationRaw.responseCheck === "string" ? manualVerificationRaw.responseCheck : undefined
            }
          : undefined;

      return {
        ...cloneTest(local),
        enabled: typeof data?.enabled === "boolean" ? data.enabled : local.engineEnabled,
        manualVerification
      };
    } catch {
      return cloneTest(local);
    }
  },

  async patchEnabled(id: string, enabled: boolean): Promise<{ id: string; enabled: boolean }> {
    try {
      const res = await fetch(`${API}/api/tests/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        // Fallback for environments without backend endpoint yet.
        return { id, enabled };
      }
      return { id, enabled: typeof data?.enabled === "boolean" ? data.enabled : enabled };
    } catch {
      return { id, enabled };
    }
  }
};

function useTests() {
  const queryClient = useQueryClient();

  const listQuery = useQuery({
    queryKey: ["catalog-tests"],
    queryFn: () => testCatalogApi.list()
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => testCatalogApi.patchEnabled(id, enabled),
    onMutate: async ({ id, enabled }) => {
      await queryClient.cancelQueries({ queryKey: ["catalog-tests"] });
      const prevList = queryClient.getQueryData<TestCatalogEntry[]>(["catalog-tests"]);
      const prevDetail = queryClient.getQueryData<TestCatalogDetail>(["catalog-tests", "detail", id]);

      queryClient.setQueryData<TestCatalogEntry[]>(["catalog-tests"], (current) =>
        (current ?? []).map((item) => (item.id === id ? { ...item, enabled } : item))
      );
      queryClient.setQueryData<TestCatalogDetail>(["catalog-tests", "detail", id], (current) =>
        current ? { ...current, enabled } : current
      );

      return { prevList, prevDetail, id };
    },
    onError: (_error, _vars, ctx) => {
      if (!ctx) return;
      if (ctx.prevList) queryClient.setQueryData(["catalog-tests"], ctx.prevList);
      if (ctx.prevDetail) queryClient.setQueryData(["catalog-tests", "detail", ctx.id], ctx.prevDetail);
    },
    onSuccess: (data) => {
      queryClient.setQueryData<TestCatalogEntry[]>(["catalog-tests"], (current) =>
        (current ?? []).map((item) => (item.id === data.id ? { ...item, enabled: data.enabled } : item))
      );
      queryClient.setQueryData<TestCatalogDetail>(["catalog-tests", "detail", data.id], (current) =>
        current ? { ...current, enabled: data.enabled } : current
      );
    }
  });

  return {
    ...listQuery,
    tests: listQuery.data ?? [],
    setEnabled: (id: string, enabled: boolean) => toggleMutation.mutate({ id, enabled }),
    isUpdating: toggleMutation.isPending,
    updatingId: toggleMutation.variables?.id ?? null
  };
}

function useTestDetails(id: string | null) {
  return useQuery({
    queryKey: ["catalog-tests", "detail", id],
    queryFn: () => testCatalogApi.getById(String(id)),
    enabled: !!id
  });
}

function readCatalogHashId() {
  if (typeof window === "undefined") return "";
  try {
    return decodeURIComponent(window.location.hash.replace(/^#/, "").trim());
  } catch {
    return window.location.hash.replace(/^#/, "").trim();
  }
}

function isCatalogOpenedFromRunningPreview() {
  if (typeof window === "undefined") return false;
  return new URLSearchParams(window.location.search).get("from") === "running-preview";
}

function formatCatalogCopy(text: string) {
  return text
    .replace(/\bBaseline behavior\b/g, "Zachowanie linii bazowej")
    .replace(/\bbaseline\b/gi, "linia bazowa")
    .replace(/\bstructured evidence\b/gi, "ustrukturyzowane dowody")
    .replace(/\bfalse negatives\b/gi, "przeoczenia (false negatives)")
    .replace(/\bbrowser-based verification\b/gi, "weryfikacja w przeglądarce")
    .replace(/\bResponse validation\b/g, "Walidacja odpowiedzi")
    .replace(/\bConcurrency\b/g, "Równoległość")
    .replace(/\bThrottle\b/g, "Ograniczanie tempa (throttle)")
    .replace(/\brobustness\b/gi, "odporności")
    .replace(/\bfallbackować\b/gi, "przełączyć");
}

export default function TestCatalog() {
  return <TestCatalogPage />;
}

function TestCatalogPage() {
  const { tests, isLoading, isError, error } = useTests();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const filtered = tests;

  const selectedIndex = useMemo(() => filtered.findIndex((t) => t.id === selectedId), [filtered, selectedId]);
  const selectedPrevId = selectedIndex > 0 ? filtered[selectedIndex - 1]?.id ?? null : null;
  const selectedNextId = selectedIndex >= 0 && selectedIndex < filtered.length - 1 ? filtered[selectedIndex + 1]?.id ?? null : null;

  const availableTests = tests.length;
  const securityTests = tests.filter((t) => {
    const type = mapCategoryToType(t.category);
    return type === "Testy bezpieczeństwa";
  }).length;
  const qualityTests = tests.filter((t) => mapCategoryToType(t.category) === "Testy jakości").length;

  useEffect(() => {
    const applyHashSelection = () => {
      const hashId = readCatalogHashId();
      if (!hashId) return;
      if (TESTS.some((t) => t.id === hashId)) {
        setSelectedId(hashId);
      }
    };

    applyHashSelection();
    window.addEventListener("hashchange", applyHashSelection);
    return () => window.removeEventListener("hashchange", applyHashSelection);
  }, []);

  return (
    <Box>
      <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }}>
        <Box>
          <Typography variant="h2">Katalog testów</Typography>
          <Typography sx={{ color: "text.secondary", mt: 0.5 }}>
            Lista problemów bezpieczeństwa wykrywanych przez skaner oraz informacje, w jaki sposób są rozpoznawane.
          </Typography>
        </Box>
      </Stack>

      <Box
        sx={{
          width: "100%",
          mr: 0
        }}
      >
        <Paper sx={{ mt: 3, p: 2.5 }}>
          <Typography sx={{ fontWeight: 700 }}>Przegląd implementacji</Typography>
          <Divider sx={{ my: 1.5 }} />
          <Grid container spacing={1.5}>
            <Grid size={{ xs: 6, md: 4 }}>
              <Stat label="Dostępne testy" value={availableTests} />
            </Grid>
            <Grid size={{ xs: 6, md: 4 }}>
              <Stat label="Testy bezpieczeństwa" value={securityTests} />
            </Grid>
            <Grid size={{ xs: 6, md: 4 }}>
              <Stat label="Testy jakości" value={qualityTests} />
            </Grid>
          </Grid>
        </Paper>

        {isError ? (
          <Alert severity="error" sx={{ mt: 2 }}>
            {(error as Error)?.message ?? "Nie udało się wczytać katalogu testów."}
          </Alert>
        ) : null}

        <Alert severity="info" variant="outlined" sx={{ mt: 2 }}>
          Kliknij nazwę podatności, aby otworzyć panel szczegółów testu.
        </Alert>

        <Paper
          sx={{
            mt: 2,
            p: 0,
            overflow: "hidden"
          }}
        >
          <TestsTable
            rows={filtered}
            loading={isLoading}
            selectedId={selectedId}
            onRowClick={(id) => setSelectedId(id)}
          />
        </Paper>
      </Box>

      <TestDetailsDrawer
        testId={selectedId}
        open={!!selectedId}
        onClose={() => {
          setSelectedId(null);
          if (typeof window !== "undefined" && window.location.hash) {
            history.replaceState(null, "", window.location.pathname + window.location.search);
          }
        }}
        onSelectPrev={selectedPrevId ? () => setSelectedId(selectedPrevId) : undefined}
        onSelectNext={selectedNextId ? () => setSelectedId(selectedNextId) : undefined}
      />
    </Box>
  );
}

type TestsTableProps = {
  rows: TestCatalogEntry[];
  loading: boolean;
  selectedId: string | null;
  onRowClick: (id: string) => void;
};

function TestsTable(props: TestsTableProps) {
  const { rows, loading, selectedId, onRowClick } = props;
  const compressed = true;

  if (loading) {
    return (
      <Stack spacing={1.25} sx={{ p: 2 }}>
        {Array.from({ length: 6 }).map((_, idx) => (
          <Skeleton key={idx} variant="rounded" height={46} />
        ))}
      </Stack>
    );
  }

  if (!rows.length) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography sx={{ color: "text.secondary" }}>Brak dostępnych testów.</Typography>
      </Box>
    );
  }

  return (
    <TableContainer sx={{ maxHeight: "calc(100vh - 340px)" }}>
      <Table stickyHeader size="small" sx={compressed ? { tableLayout: "fixed" } : undefined}>
        <TableHead>
          <TableRow>
            <TableCell sx={{ width: "25%", px: 1.25, py: 1.25 }}>
              Podatność
            </TableCell>
            <TableCell sx={{ width: "25%", px: 1.25, py: 1.25 }}>
              Typ
            </TableCell>
            <TableCell sx={{ width: "25%", px: 1.25, py: 1.25 }}>
              Ryzyko
            </TableCell>
            <TableCell sx={{ width: "25%", px: 1.25, py: 1.25 }}>
              Miejsce testu
            </TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((row) => {
            const selected = selectedId === row.id;
            return (
              <TableRow
                key={row.id}
                hover
                selected={selected}
                onClick={() => onRowClick(row.id)}
                tabIndex={0}
                sx={{ cursor: "pointer", "& > td": { py: 1.1 } }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onRowClick(row.id);
                  }
                }}
              >
                <TableCell sx={{ px: 1.25 }}>
                  <Stack spacing={0.4} sx={compressed ? { minWidth: 0 } : undefined}>
                    <Typography
                      sx={{
                        fontWeight: 700,
                        fontSize: 13.5,
                        ...(compressed
                          ? {
                              whiteSpace: "nowrap",
                              overflow: "hidden",
                              textOverflow: "ellipsis"
                            }
                          : {})
                      }}
                      title={row.name}
                    >
                      {row.name}
                    </Typography>
                  </Stack>
                </TableCell>
                <TableCell sx={{ px: 1.25 }}>
                  <Chip
                    size="small"
                    color={categoryColor(row.category) as any}
                    label={mapCategoryToType(row.category)}
                    variant="outlined"
                    sx={typeChipSx(row.category)}
                  />
                </TableCell>
                <TableCell sx={{ px: 1.25 }}>
                  <Chip
                    size="small"
                    label={getCatalogSeverity(row.id)}
                    variant="outlined"
                    sx={severityChipSx(getCatalogSeverity(row.id))}
                  />
                </TableCell>
                <TableCell sx={{ px: 1.25 }}>
                  <Typography
                    sx={{
                      fontSize: 12.5,
                      color: "text.secondary",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis"
                    }}
                    title={getCatalogSurfaceLabel(row.id)}
                  >
                    {getCatalogSurfaceLabel(row.id)}
                  </Typography>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

type TestDetailsDrawerProps = {
  testId: string | null;
  open: boolean;
  onClose: () => void;
  onSelectPrev?: () => void;
  onSelectNext?: () => void;
};

function TestDetailsDrawer(props: TestDetailsDrawerProps) {
  const { testId, open, onClose, onSelectPrev, onSelectNext } = props;
  const detailsQuery = useTestDetails(testId);
  const item = detailsQuery.data ?? null;
  const showBackButton = isCatalogOpenedFromRunningPreview();

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      ModalProps={{ keepMounted: true }}
      PaperProps={{
        sx: {
          width: { xs: "100%", md: 620 },
          p: 0,
          overflowY: "auto"
        }
      }}
    >
      <Box sx={{ position: "sticky", top: 0, zIndex: 2, bgcolor: "background.paper", borderBottom: "1px solid", borderColor: "divider" }}>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ px: 2, py: 1.25 }}>
          <Typography sx={{ fontWeight: 700, flex: 1 }}>Szczegóły testu</Typography>
          <IconButton onClick={onSelectPrev} disabled={!onSelectPrev} aria-label="Poprzedni test">
            <ChevronLeftIcon />
          </IconButton>
          <IconButton onClick={onSelectNext} disabled={!onSelectNext} aria-label="Następny test">
            <ChevronRightIcon />
          </IconButton>
          <IconButton onClick={onClose} aria-label="Zamknij panel szczegółów">
            <CloseIcon />
          </IconButton>
        </Stack>
      </Box>

      <Box sx={{ p: 2 }}>
        {detailsQuery.isLoading ? (
          <Stack spacing={1.25}>
            <Skeleton variant="rounded" height={28} />
            <Skeleton variant="rounded" height={22} />
            <Skeleton variant="rounded" height={120} />
            <Skeleton variant="rounded" height={260} />
          </Stack>
        ) : detailsQuery.isError ? (
          <Alert severity="error">{(detailsQuery.error as Error)?.message ?? "Nie udało się pobrać szczegółów testu."}</Alert>
        ) : !item ? (
          <Alert severity="info">Wybierz test z listy po lewej stronie.</Alert>
        ) : (
          <Stack spacing={2}>
            <Stack spacing={1}>
              <Typography variant="h6" sx={{ lineHeight: 1.2 }}>{item.name}</Typography>
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip
                  size="small"
                  color={categoryColor(item.category) as any}
                  label={mapCategoryToType(item.category)}
                  sx={typeChipSx(item.category)}
                />
              </Stack>
              <Typography sx={{ fontSize: 13, color: "text.secondary" }}>{formatCatalogCopy(item.short)}</Typography>
            </Stack>

            <Section title="Cel testu" items={[item.goal]} />
            <Section title="Zakres" items={item.scope} />
            <Section title="Jak działa" items={item.mechanism} />
            <Section title="Klasyfikacja wyników" items={item.verdicts} />
            <Section title="Jak ograniczamy false positives" items={item.falsePositiveControls} />
            <Section title="Ograniczenia" items={item.limitations} />
            <Section title="Przykłady dowodów" items={item.evidenceExamples} />
            {showBackButton ? (
              <Box sx={{ pt: 1 }}>
                <Button fullWidth variant="outlined" onClick={() => window.history.back()}>
                  Wróć
                </Button>
              </Box>
            ) : null}
          </Stack>
        )}
      </Box>
    </Drawer>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <Paper variant="outlined" sx={{ p: 1.25 }}>
      <Typography sx={{ fontSize: 12, color: "text.secondary" }}>{label}</Typography>
      <Typography sx={{ fontWeight: 700, fontSize: 18 }}>{value}</Typography>
    </Paper>
  );
}

function Section({ title, items }: { title: string; items: string[] }) {
  return (
    <Box>
      <Typography sx={{ fontSize: 13, fontWeight: 700 }}>{title}</Typography>
      <Box component="ul" sx={{ my: 0.75, pl: 2.5 }}>
        {items.map((line) => (
          <li key={`${title}-${line}`}>
            <Typography sx={{ fontSize: 13, color: "text.secondary" }}>{formatCatalogCopy(line)}</Typography>
          </li>
        ))}
      </Box>
    </Box>
  );
}
