#include <iostream>
#include <limits> // Pour numeric_limits

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

    while (true) {
        std::cout << "[] ";
        std::cin >> choix;

        // Vérifier si la saisie a réussi (si un entier a été entré)
        if (std::cin.good()) {
            break; // Sortir de la boucle si la saisie est valide
        }
        else {
            std::cout << "Erreur : Veuillez entrer un nombre entier." << std::endl;
            // Effacer les erreurs du flux d'entrée
            std::cin.clear();
            // Ignorer le reste de la ligne d'entrée
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    }

    std::cout << "Vous avez choisi l'option : " << choix << std::endl;

    // Vous pouvez maintenant utiliser la variable 'choix' pour effectuer
    // les actions correspondantes au menu.

    return 0;
}