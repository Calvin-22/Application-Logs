#include <iostream>
#include <limits> // Pour numeric_limits

// Déclarations de fonctions 
void afficherLogSudo() {
    std::cout << "Fonctionnalite pour afficher le log sudo en cours..." << std::endl;
    // Ici, vous mettriez le code pour afficher le log sudo
}

void afficherEtEnregistrerLogSsh() {
    std::cout << "Fonctionnalite pour afficher et enregistrer le log ssh en cours..." << std::endl;
    // Ici, vous mettriez le code pour afficher et enregistrer le log ssh
}

void sortirDuProgramme() {
    std::cout << "Sortie du programme..." << std::endl;
    // Ici, vous mettriez le code pour nettoyer avant de quitter (si nécessaire)
}

// Affichage du menu
int main() {
    int choix;

    std::cout << "CIEL - Gestion centralisee de logs" << std::endl;
    std::cout << "Menu" << std::endl;
    std::cout << "Choisir une option" << std::endl;
    std::cout << "1 - Afficher log sudo" << std::endl;
    std::cout << "2 - Afficher et enregistrer log ssh" << std::endl;
    std::cout << "0 - Sortir du programme" << std::endl;
    std::cout << std::endl;

    // Lancement de la saisie
    while (true) {
        std::cout << "[] ";
        std::cin >> choix;

        if (std::cin.good()) {
            break;
        }
        else {
            std::cout << "Erreur : Veuillez entrer un nombre entier." << std::endl;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    }

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
        break;
    default:
        std::cout << "Option invalide." << std::endl;
        break;
    }

    return 0;
}