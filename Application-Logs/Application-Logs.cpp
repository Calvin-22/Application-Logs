// Application de gestion des logs
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

// Nom du fichier de log
const std::string LOG_FILE = "windows_system_logs.txt";

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

void afficherLogSudo() {
    std::cout << "--- Logs Sudo, Connexions Locales et Événements Critiques (Temps Réel et Enregistrement - UTF-8) ---\n";
    std::ofstream logFile(LOG_FILE, std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << getCurrentTimestamp() << "] --- DEBUT DE LA RECUPERATION DES LOGS WINDOWS (UTF-8) ---\n";

        auto writeLogEntry = [&](const std::wstring& entryW) {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string entryUTF8 = converter.to_bytes(entryW);
            std::wcout << entryW; // Affichage Unicode sur la console (si configurée)
            logFile << entryUTF8;
            };

        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

        auto readAndDisplayEventsW = [&](const wchar_t* logName, const std::wstring& eventTypeFilterW) {
            HANDLE hEventLog = OpenEventLogW(NULL, logName);
            if (hEventLog != NULL) {
                writeLogEntry(L"[" + converter.from_bytes(getCurrentTimestamp()) + L"] Ouverture du journal '" + logName + L"' (UTF-8) réussie.\n");

                DWORD dwRead = 0;
                DWORD dwNeeded = 0;
                std::vector<BYTE> buffer(8192);
#ifndef EVENTLOG_FORWARD_READ
#define EVENTLOG_FORWARD_READ 0x00000004 // Define the missing constant
#endif

                while (ReadEventLogW(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARD_READ, 0, buffer.data(), buffer.size(), &dwRead, &dwNeeded)) {
                    if (dwRead > 0) {
                        EVENTLOGRECORD* pRecord = reinterpret_cast<EVENTLOGRECORD*>(buffer.data());
                        DWORD offset = 0;
                        while (offset < dwRead) {
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
                            logEntrySSW << L"[" << timeSSW.str() << L"] [" << eventTypeFilterW << L"] [" << sourceNameW << L"] " << messageW << L"\n";
                            writeLogEntry(logEntrySSW.str());

                            offset += pRecord->Length;
                            pRecord = reinterpret_cast<EVENTLOGRECORD*>(reinterpret_cast<BYTE*>(pRecord) + pRecord->Length);
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
                std::wcerr << L"[" << converter.from_bytes(getCurrentTimestamp()) << L"] Erreur lors de l'ouverture du journal '" << logName << L"' (UTF-8) : " << dwError << L"\n";
                logFile << "[" << getCurrentTimestamp() << "] Erreur lors de l'ouverture du journal '" << converter.to_bytes(logName) << "' (UTF-8) : " << dwError << "\n";
            }
            };

        std::wcout << L"\n--- Journal de Sécurité (UTF-8) ---\n";
        readAndDisplayEventsW(L"Security", L"SECURITE");

        std::wcout << L"\n--- Journal Système (Événements Critiques - UTF-8) ---\n";
        HANDLE hSystemLog = OpenEventLogW(NULL, L"System");
        if (hSystemLog != NULL) {
            writeLogEntry(L"[" + converter.from_bytes(getCurrentTimestamp()) + L"] Ouverture du journal 'System' réussie (filtrage des événements critiques - UTF-8).\n");
            DWORD dwRead = 0;
            DWORD dwNeeded = 0;
            std::vector<BYTE> buffer(8192);
#ifndef EVENTLOG_FORWARD_READ
#define EVENTLOG_FORWARD_READ 0x00000004 // Define the missing constant
#endif

#ifndef EVENTLOG_CRITICAL_TYPE
#define EVENTLOG_CRITICAL_TYPE 0x0001 // Define a placeholder value for critical event type
#endif
            while (ReadEventLogW(hSystemLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARD_READ, 0, buffer.data(), buffer.size(), &dwRead, &dwNeeded)) {
                if (dwRead > 0) {
                    EVENTLOGRECORD* pRecord = reinterpret_cast<EVENTLOGRECORD*>(buffer.data());
                    DWORD offset = 0;
                    while (offset < dwRead) {
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
                            logEntrySSW << L"[" << timeSSW.str() << L"] [CRITIQUE] [" << sourceNameW << L"] " << messageW << L"\n";
                            writeLogEntry(logEntrySSW.str());
                        }
                        offset += pRecord->Length;
                        pRecord = reinterpret_cast<EVENTLOGRECORD*>(reinterpret_cast<BYTE*>(pRecord) + pRecord->Length);
                    }
                }
                else {
                    break;
                }
            }
            CloseEventLog(hSystemLog);
            writeLogEntry(L"[" + converter.from_bytes(getCurrentTimestamp()) + L"] Fermeture du journal 'System' (UTF-8).\n");
        }
        else {
            DWORD dwError = GetLastError();
            std::wcerr << L"[" << converter.from_bytes(getCurrentTimestamp()) << L"] Erreur lors de l'ouverture du journal 'System' (UTF-8) : " << dwError << L"\n";
            logFile << "[" << getCurrentTimestamp() << "] Erreur lors de l'ouverture du journal 'System' (UTF-8) : " << dwError << "\n";
        }

        logFile << "[" << getCurrentTimestamp() << "] --- FIN DE LA RECUPERATION DES LOGS WINDOWS (UTF-8) ---\n\n";
        logFile.close();
        std::cout << "Les informations ont été enregistrées dans : " << LOG_FILE << std::endl;
    }
    else {
        std::cerr << "Erreur lors de l'ouverture du fichier de log : " << LOG_FILE << std::endl;
    }
}

void afficherEtEnregistrerLogSsh() {
    std::cout << "Fonctionnalite pour afficher et enregistrer le log ssh en cours..." << std::endl;
    std::cout << "La gestion des logs SSH est généralement spécifique aux systèmes de type Unix.\n";
    std::cout << "Sur Windows, vous pouvez examiner le journal 'Security' pour des tentatives de connexion.\n";
    // Ici, vous pourriez ajouter du code spécifique à Windows pour rechercher des événements liés à des connexions réseau ou d'authentification (en utilisant l'API Wide).
}

void sortirDuProgramme() {
    std::cout << "Sortie du programme..." << std::endl;
    // Ici, vous mettriez le code pour nettoyer avant de quitter (si nécessaire)
}

// Affichage du menu
int main() {
    // Configuration de la locale pour la sortie wcout (UTF-8)
    std::locale::global(std::locale(""));
    std::wcout.imbue(std::locale());
    std::wcerr.imbue(std::locale());

    int choix;

    while (true) {
        std::cout << "CIEL - Gestion centralisée de logs" << std::endl;
        std::cout << "Menu" << std::endl;
        std::cout << "Choisir une option" << std::endl;
        std::cout << "1 - Afficher log sudo" << std::endl;
        std::cout << "2 - Afficher et enregistrer log ssh" << std::endl;
        std::cout << "0 - Sortir du programme" << std::endl;
        std::cout << std::endl;

        // Lancement de la saisie
        std::cout << "[] ";
        std::cin >> choix;

        if (std::cin.good()) {
            // Affichage de la valeur saisie
            std::cout << "Vous avez choisi l'option : " << choix << std::endl;

            // Lancement du programme en fonction de la valeur saisie
            switch (choix) {
            case 1:
                afficherLogSudo();
                break;
            case 2:
                afficherEtEnregistrerLogSsh();
                break;
            case 0:
                sortirDuProgramme();
                return 0; // Sortir définitivement si l'utilisateur choisit 0
            default:
                std::cout << "Option invalide." << std::endl;
                break;
            }
        }
        else {
            std::cout << "Erreur : Veuillez entrer un nombre entier." << std::endl;
            std::cin.clear();
            while (std::cin.peek() != '\n' && std::cin.peek() != EOF) {
                std::cin.get();
            }
            if (std::cin.peek() == '\n') {
                std::cin.get(); // Consommer le caractère de nouvelle ligne
            }
        }
        std::cout << std::endl; // Ajouter une ligne vide pour la prochaine itération
    }

    return 0; // Cette ligne ne sera atteinte qu'en cas d'erreur hors de la boucle
}