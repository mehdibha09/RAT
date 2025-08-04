#include <windows.h>
#include <iostream>

int main() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // Le processus que tu veux lancer en mode suspendu (exemple : notepad)
    LPCSTR targetProcess = "C:\\Windows\\System32\\notepad.exe";

    BOOL success = CreateProcessA(
        targetProcess,     // Nom de l'exécutable
        NULL,              // Arguments
        NULL,              // Sécurité processus
        NULL,              // Sécurité thread
        FALSE,             // Héritage des handles
        CREATE_SUSPENDED,  // <== Création en mode suspendu
        NULL,              // Environnement
        NULL,              // Répertoire courant
        &si,               // Info startup
        &pi                // Info process (rempli à la sortie)
    );

    if (success) {
        std::cout << "[+] Processus suspendu créé avec succès !" << std::endl;
        std::cout << "    PID : " << pi.dwProcessId << std::endl;

        // On ne reprend pas encore le thread ici — process reste gelé
        // ResumeThread(pi.hThread); // => à faire après hollowing
    }
    else {
        std::cerr << "[-] Échec de la création du processus." << std::endl;
        std::cerr << "    Code d’erreur : " << GetLastError() << std::endl;
    }

    // On garde les handles ouverts pour manipulation mémoire
    return 0;
}
