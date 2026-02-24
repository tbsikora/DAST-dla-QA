# DAST dla QA — Automatyczny system testowania bezpieczeństwa API

Webowa aplikacja wspierająca testerów QA w **automatycznym testowaniu bezpieczeństwa API** metodą **DAST (Dynamic Application Security Testing)** na podstawie specyfikacji OpenAPI.

W katalogu głównym projektu znajduje się przykładowa specyfikacja **OpenAPI**:
`petstore.json`

Można jej użyć od razu po uruchomieniu aplikacji.

**Testowe API:**
https://petstore.swagger.io/v2

**Swagger / edytor specyfikacji:**
https://petstore.swagger.io/

**Hostowana wersja aplikacji (demo):**
https://web-production-a6a06.up.railway.app/

**Repozytorium GitHub:**
https://github.com/tbsikora/DAST-dla-QA

System umożliwia:

* wczytanie specyfikacji OpenAPI
* konfigurację skanu (uwierzytelnianie, profil testów, seedowanie danych)
* uruchomienie skanu i śledzenie jego przebiegu
* przegląd historii skanów
* eksport wyników
* podgląd katalogu testów bezpieczeństwa

---

## Tech stack

**Frontend**

* React
* TypeScript
* Vite
* MUI

**Backend**

* Node.js
* Express
* TypeScript

**Silnik skanera**

* autorska implementacja DAST dla REST API

---

## Struktura repozytorium

```
apps/
  web/   -> frontend (interfejs użytkownika)
  api/   -> backend + silnik skanera
```

---

## Wymagania

* Node.js 20+
* Yarn 1.22.x

---

## Szybki start (lokalnie)

### 1. Instalacja zależności

```bash
yarn install
```

### 2. Uruchom backend

```bash
yarn dev:api
```

Backend:

```
http://localhost:4000
```

### 3. Uruchom frontend (w drugim terminalu)

```bash
yarn dev:web
```

Frontend:

```
http://localhost:5173
```

Frontend w trybie developerskim automatycznie przekazuje `/api` do backendu (`localhost:4000`).

---

## Uruchomienie przez Docker

```bash
docker compose up --build
```

Adresy:

* Frontend: http://localhost:8080
* Backend: http://localhost:4000

Zatrzymanie:

```bash
docker compose down
```

---

## Zmienne środowiskowe

Plik `.env` **nie jest wymagany do uruchomienia aplikacji** — projekt działa na domyślnej konfiguracji zaraz po instalacji i starcie serwerów.

Zmienne środowiskowe pozwalają nadpisać ustawienia (np. port, logowanie HTTP, zapis historii skanów) lub dostosować aplikację do innego środowiska (Docker, inny host backendu itp.).

W repo znajduje się przykładowa konfiguracja: `.env.example`.

### Backend (`apps/api`)

| Zmienna                   | Opis                                  | Domyślna wartość  |
| ------------------------- | ------------------------------------- | ----------------- |
| `PORT`                    | port API                              | 4000              |
| `DAST_HTTP_TRACE`         | logowanie requestów skanera w konsoli | 0                 |
| `DAST_HTTP_DEBUG_CAPTURE` | zapis request/response w wynikach     | 0                 |
| `DAST_DB_FILE`            | plik historii skanów                  | lokalny plik JSON |

Po włączeniu `DAST_HTTP_DEBUG_CAPTURE` wyniki zawierają pełne requesty i odpowiedzi HTTP użyte podczas testów.

### Frontend (`apps/web`)

| Zmienna        | Opis                                                                          |
| -------------- | ----------------------------------------------------------------------------- |
| `VITE_API_URL` | adres backendu (opcjonalny; potrzebny np. przy uruchomieniu poza localhostem) |

---

## Informacja bezpieczeństwa

System jest narzędziem do **aktywnego testowania bezpieczeństwa API**.

Uruchamianie skanów na systemach bez zgody właściciela może naruszać prawo lub regulaminy usług.
