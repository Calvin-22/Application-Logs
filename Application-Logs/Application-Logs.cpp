// Application de supervision de PC - Focus Authentification et Privilèges
// Le 11/05/2025 
// Par Calvin
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <windows.h>
#include <vector>
#include <chrono>
#include <locale>
#include <codecvt>
#include <shlobj.h>

// Nom du fichier de log
const std::wstring LOG_FILE_NAME_W = L"supervision_securite.txt";
std::string logFilePath;
const DWORD MAX_EVENTS_TO_READ = 100; // Augmentation de la limite pour capturer plus d'événements pertinents

// ID d'événement courants pour l'authentification (à adapter)
const DWORD EVENT_ID_CONNEXION_REUSSIE = 4624;
const DWORD EVENT_ID_ECHEC_CONNEXION = 4625;
const DWORD EVENT_ID_DECONNEXION = 4634;
const DWORD EVENT_ID_VERROUILLAGE_COMPTE = 4740;
const DWORD EVENT_ID_DEVERROUILLAGE_COMPTE = 4767;

// ID d'événement courants pour l'élévation de privilèges (UAC) (à adapter)
const DWORD EVENT_ID_UAC_DEMANDE_ELEVATION = 4690; // Tentative d’effectuer une opération nécessitant des privilèges élevés
const DWORD EVENT_ID_UAC_PROCESSUS_ELEVEE = 4104;   // (Microsoft-Windows-User Account Control) - Démarrage d'une application avec élévation

// Fonction pour obtenir le chemin du bureau de l'utilisateur en Unicode
std::wstring getDesktopPathW() {
    wchar_t* path = nullptr;
    HRESULT hr = SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, path);
    if (SUCCEEDED(hr) && path != nullptr) {
        std::wstring desktopPath(path);
        CoTaskMemFree(path);
        return desktopPath + L"\\";
    }
    else {
        std::wcerr << L"Erreur lors de la récupération du chemin du bureau." << std::endl;
        return L"";
    }
}

// Fonction pour obtenir la date et l'heure actuelles au format AAAA-MM-JJ HH:MM:SS
std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm;
    localtime_s(&now_tm, &now_c);
    std::stringstream ss;
    ss << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void surveillerSecurite() {
    std::wcout << L"--- Surveillance de Sécurité (Authentification et Élévation de Privilèges - UTF-8) ---\n";
    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << getCurrentTimestamp() << "] --- DEBUT DE LA SURVEILLANCE DE SECURITE ---\n";

        auto writeLogEntry = [&](const std::wstring& entryW) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string entryUTF8 = converter.to_bytes(entryW);
            std::wcout << entryW;
            logFile << entryUTF8;
            };

        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

        auto readAndDisplaySecurityEventsW = [&](const wchar_t* logName) {
            HANDLE hEventLog = OpenEventLogW(NULL, logName);
            if (hEventLog != NULL) {
                writeLogEntry(L"[" + converter.from_bytes(getCurrentTimestamp()) + L"] Ouverture du journal '" + logName + L"' (UTF-8) réussie (filtrage: authentification, UAC).\n");

                DWORD dwRead = 0;
                DWORD dwNeeded = 0;
                std::vector<BYTE> buffer(8192);
                DWORD eventsRead = 0;

#ifndef EVENTLOG_FORWARD_READ
#define EVENTLOG_FORWARD_READ 0x00000004
#endif

                while (ReadEventLogW(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARD_READ, 0, buffer.data(), buffer.size(), &dwRead, &dwNeeded) && eventsRead < MAX_EVENTS_TO_READ) {
                    if (dwRead > 0) {
                        EVENTLOGRECORD* pRecord = reinterpret_cast<EVENTLOGRECORD*>(buffer.data());
                        DWORD offset = 0;
                        while (offset < dwRead && eventsRead < MAX_EVENTS_TO_READ) {
                            std::time_t eventTime = pRecord->TimeGenerated;
                            std::tm tm_event;
                            localtime_s(&tm_event, &eventTime);
                            std::wstringstream timeSSW;
                            timeSSW << std::put_time(&tm_event, L"%Y-%m-%d %H:%M:%S");

                            wchar_t* pSourceNameW = reinterpret_cast<wchar_t*>(reinterpret_cast<BYTE*>(pRecord) + sizeof(EVENTLOGRECORD));
                            std::wstring sourceNameW(pSourceNameW);

                            LPWSTR pStringsW = reinterpret_cast<LPWSTR>(reinterpret_cast<BYTE*>(pSourceNameW) + (wcslen(pSourceNameW) + 1) * sizeof(wchar_t));
                            std::wstring messageW;
                            for (DWORD i = 0; i < pRecord->NumStrings; ++i) {
                                messageW += pStringsW;
                                if (i < pRecord->NumStrings - 1) {
                                    messageW += L" ";
                                }
                                pStringsW += wcslen(pStringsW) + 1;
                            }

                            // Filtrage des événements d'authentification et d'élévation de privilèges
                            if (pRecord->EventID == EVENT_ID_CONNEXION_REUSSIE ||
                                pRecord->EventID == EVENT_ID_ECHEC_CONNEXION ||
                                pRecord->EventID == EVENT_ID_DECONNEXION ||
                                pRecord->EventID == EVENT_ID_VERROUILLAGE_COMPTE ||
                                pRecord->EventID == EVENT_ID_DEVERROUILLAGE_COMPTE ||
                                pRecord->EventID == EVENT_ID_UAC_DEMANDE_ELEVATION ||
                                pRecord->EventID == EVENT_ID_UAC_PROCESSUS_ELEVEE)
                            {
                                std::wstringstream logEntrySSW;
                                logEntrySSW << L"[" << timeSSW.str() << L"] [SECURITE] [" << sourceNameW << L"] (ID: " << pRecord->EventID << L") " << messageW << L"\n";
                                writeLogEntry(logEntrySSW.str());
                            }

                            offset += pRecord->Length;
                            pRecord = reinterpret_cast<EVENTLOGRECORD*>(reinterpret_cast<BYTE*>(pRecord) + pRecord->Length);
                            eventsRead++;
                        }
                    }
                    else {
                        break;
                    }
                }
                CloseEventLog(hEventLog);
                writeLogEntry(L"[" + converter.from_bytes(getCurrentTimestamp()) + L"] Fermeture du journal '" + logName + L"' (UTF-8).\n");
            }
            else {
                DWORD dwError = GetLastError();
                std::wcerr << L"[" << converter.from_bytes(getCurrentTimestamp()) + L"] Erreur lors de l'ouverture du journal '" << logName << L"' (UTF-8) : " << dwError << L"\n";
                logFile << "[" << getCurrentTimestamp() << "] Erreur lors de l'ouverture du journal '" << converter.to_bytes(logName) << "' (UTF-8) : " << dwError << "\n";
            }
            };

        readAndDisplaySecurityEventsW(L"Security");

        logFile << "[" << getCurrentTimestamp() << "] --- FIN DE LA SURVEILLANCE DE SECURITE ---\n\n";
        logFile.close();
        std::cout << "Les informations de sécurité ont été enregistrées sur votre bureau : " << logFilePath << std::endl;
    }
    else {
        std::cerr << "Erreur lors de l'ouverture du fichier de log : " << logFilePath << std::endl;
    }
}

void surveillerSystemeCritique() {
    std::wcout << L"--- Surveillance Système (Erreurs, Critiques, Avertissements - UTF-8) ---\n";
    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << getCurrentTimestamp() << "] --- DEBUT DE LA SURVEILLANCE SYSTEME (CRITIQUE) ---\n";

        auto writeLogEntry = [&](const std::wstring& entryW) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string entryUTF8 = converter.to_bytes(entryW);
            std::wcout << entryW;
            logFile << entryUTF8;
            };

        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

        auto readAndDisplaySystemEventsW = [&](const wchar_t* logName) {
            HANDLE hEventLog = OpenEventLogW(NULL, logName);
            if (hEventLog != NULL) {
                writeLogEntry(L"[" + converter.from_bytes(getCurrentTimestamp()) + L"] Ouverture du journal '" + logName + L"' (UTF-8) réussie (filtrage: erreurs, critiques, avertissements).\n");

                DWORD dwRead = 0;
                DWORD dwNeeded = 0;
                std::vector<BYTE> buffer(8192);
                DWORD eventsRead = 0;

#ifndef EVENTLOG_FORWARD_READ
#define EVENTLOG_FORWARD_READ 0x00000004
#endif

#ifndef EVENTLOG_CRITICAL_TYPE
#define EVENTLOG_CRITICAL_TYPE 0x0001
#endif
                while (ReadEventLogW(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARD_READ, 0, buffer.data(), buffer.size(), &dwRead, &dwNeeded) && eventsRead < MAX_EVENTS_TO_READ) {
                    if (dwRead > 0) {
                        EVENTLOGRECORD* pRecord = reinterpret_cast<EVENTLOGRECORD*>(buffer.data());
                        DWORD offset = 0;
                        while (offset < dwRead && eventsRead < MAX_EVENTS_TO_READ) {
                            if (pRecord->EventType == EVENTLOG_ERROR_TYPE || pRecord->EventType == EVENTLOG_CRITICAL_TYPE || pRecord->EventType == EVENTLOG_WARNING_TYPE) {
                                std::time_t eventTime = pRecord->TimeGenerated;
                                std::tm tm_event;
                                localtime_s(&tm_event, &eventTime);
                                std::wstringstream timeSSW;
                                timeSSW << std::put_time(&tm_event, L"%Y-%m-%d %H:%M:%S");

                                wchar_t* pSourceNameW = reinterpret_cast<wchar_t*>(reinterpret_cast<BYTE*>(pRecord) + sizeof(EVENTLOGRECORD));
                                std::wstring sourceNameW(pSourceNameW);

                                LPWSTR pStringsW = reinterpret_cast<LPWSTR>(reinterpret_cast<BYTE*>(pSourceNameW) + (wcslen(pSourceNameW) + 1) * sizeof(wchar_t));
                                std::wstring messageW;
                                for (DWORD i = 0; i < pRecord->NumStrings; ++i) {
                                    messageW += pStringsW;
                                    if (i < pRecord->NumStrings - 1) {
                                        messageW += L" ";
                                    }
                                    pStringsW += wcslen(pStringsW) + 1;
                                }

                                std::wstringstream logEntrySSW;
                                logEntrySSW << L"[" << timeSSW.str() << L"] [" << (pRecord->EventType == EVENTLOG_ERROR_TYPE ? L"ERREUR" : (pRecord->EventType == EVENTLOG_CRITICAL_TYPE ? L"CRITIQUE" : L"AVERTISSEMENT")) << L"] [" << sourceNameW << L"] " << messageW << L"\n";
                                writeLogEntry(logEntrySSW.str());
                            }
                            offset += pRecord->Length;
                            pRecord = reinterpret_cast<EVENTLOGRECORD*>(reinterpret_cast<BYTE*>(pRecord) + pRecord->Length);
                            eventsRead++;
                        }
                    }
                    else {
                        break;
                    }
                }
                CloseEventLog(hEventLog);
                writeLogEntry(L"[" + converter.from_bytes(getCurrentTimestamp()) + L"] Fermeture du journal '" + logName + L"' (UTF-8).\n");
            }
            else {
                DWORD dwError = GetLastError();
                std::wcerr << L"[" << converter.from_bytes(getCurrentTimestamp()) + L"] Erreur lors de l'ouverture du journal '" << logName << L"' (UTF-8) : " << dwError << L"\n";
                logFile << "[" << getCurrentTimestamp() << "] Erreur lors de l'ouverture du journal '" << converter.to_bytes(logName) << "' (UTF-8) : " << dwError << "\n";
            }
            };

        readAndDisplaySystemEventsW(L"System");

        logFile << "[" << getCurrentTimestamp() << "] --- FIN DE LA SURVEILLANCE SYSTEME (CRITIQUE) ---\n\n";
        logFile.close();
        std::cout << "Les informations système critiques ont été ajoutées au log sur votre bureau : " << logFilePath << std::endl;
    }
    else {
        std::cerr << "Erreur lors de l'ouverture du fichier de log : " << logFilePath << std::endl;
    }
}

void afficherEtEnregistrerLogSsh() {
    std::cout << "Fonctionnalite pour afficher et enregistrer le log ssh en cours..." << std::endl;
    std::cout << "La gestion des logs SSH est généralement spécifique aux systèmes de type Unix.\n";
    std::cout << "Sur Windows, vous pouvez examiner le journal 'Security' pour des tentatives de connexion.\n";
}

void sortirDuProgramme() {
    std::cout << "Sortie du programme..." << std::endl;
}

int main() {
    std::locale::global(std::locale(""));
    std::wcout.imbue(std::locale());
    std::wcerr.imbue(std::locale());

    std::wstring desktopPathW = getDesktopPathW();
    if (!desktopPathW.empty()) {
        logFilePath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(desktopPathW + LOG_FILE_NAME_W);
    }
    else {
        logFilePath = "supervision_securite.txt";
    }

    int choix;

    while (true) {
        std::cout << "CIEL - Supervision centralisee de PCs" << std::endl;
        std::cout << "Menu" << std::endl;
        std::cout << "Choisir une option" << std::endl;
        std::cout << "1 - Surveiller la sécurité (Authentification, Privilèges)" << std::endl;
        std::cout << "2 - Surveiller le système (Erreurs, Critiques, Avertissements)" << std::endl;
        std::cout << "3 - Afficher et enregistrer log ssh (non implemente)" << std::endl;
        std::cout << "0 - Sortir du programme" << std::endl;
        std::cout << std::endl;

        std::cout << "[] ";
        std::cin >> choix;

        if (std::cin.good()) {
            std::cout << "Vous avez choisi l'option : " << choix << std::endl;
            switch (choix) {
            case 1:
                surveillerSecurite();
                break;
            case 2:
                surveillerSystemeCritique();
                break;
            case 3:
                afficherEtEnregistrerLogSsh();
                break;
            case 0:
                sortirDuProgramme();
                return 0;
            default:
                std::cout << "Option invalide." << std::endl;
                break;
            }
        }
        else {
            std::cout << "Erreur : Veuillez entrer un nombre entier." << std::endl;
            std::cin.clear();
        }
    }
}
